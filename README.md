# Detrackify

Processes standard emails and tries to determine what images within are used to track you. If found, it will replace them with a embedded 1x1 transparent pixel, thus retaining the formatting but preventing the pixel from reporting in.

## Features

- Handles both HTML and non-HTML (well, then there's no tracking either)
- Adds X-Detrackify headers for statistics and debugging
- Integrates with your MTA, allowing server based tracking prevention
- Failsafe, if tool fails for some reason, will revert to passthru of the email (configurable)

## Known issues

- Will break DKIM since content and headers change, but this is expected.
- Doesn't handle elements contained within hidden elements

## Usage

`--input` and `--output` to run from command line, will also output information about what was blocked

`--message-id` to log the message id in the log output

`--verbose` enable debug logging

`--logfile` save logging to file instead of stderr

`--hardfail` instead of outputting unprocessed mail when an error occurs, it stops processing and exits with 1 (note that when run from command line, this is always the behavior)

`--stripquery` will remove any parameters attached to an image's URL, ie `https://www.shady-site.com/nice-logo.png?track=879384yutr93478` becomes `https://www.shady-site.com/nice-logo.png`. This is *experimental* and without this option the log will show what images it would strip. It's experimental because there's no guarantee that this won't break the image.

## Ubuntu installation

Please use the following apt line instead of pip3

```
apt install python3-bs4 python3-pil
```

# EXIM configuration

This assumes you're somewhat comfortable with exim4's configuration.

## Adding a transport

```
detrackify:
  driver = pipe
  transport_filter = /opt/detrackify-email/detrackify-email.py --message-id ${message_id} --logfile /var/log/exim4/detrackify.log
  use_bsmtp
  command = /usr/sbin/exim4 -oMr detrackify -bS
  return_fail_output = true
  log_output = true
```

We run this as a transport filter, to allow us to manipulate the content. Then we use `exim` to redeliver it, while also ensuring it's tagged as `detrackify` so we can avoid an infinite loop.

Should the command fail, the sender will get an email back with the output from the command, ie, `exim4`.

## Adding a new router

```
detrackify_router:
  driver = accept
  domains = +local_domains
  local_parts = someuser
  condition = ${if !eq{$received_protocol}{detrackify}{yes}{no}}
  transport = detrackify
```

Setting `local_parts` to a local user allows you to test this on a single user, instead of doing it for all users. We also make sure we're testing how we received the email. If it came via exim4 (see transport), we don't want to process this email since it has already had a run.

Due to how this all works, it's **important** that you add the router BEFORE any local delivery agents (LDA), such as dovecot, etc. But it also needs to happen after any other massaging you're doing to the email, to avoid wasting cycles on this if the email is spam.

Ideally (and what I did) you put it 2nd to last, ie, right before your LDA.

## Confirming that it works

First of all, send yourself a message. If you've configured it correctly, you can check the `mainlog` for the following:

```
2024-09-09 04:04:47 1snTln-00000002pCO-24ge <= some@email.address.com U=Debian-exim P=detrackify S=85164 id=1006251088.8949486.1725847483059@address.com
2024-09-09 04:04:48 1snTln-00000002pCO-24ge => Me <my@email.com> R=virtual_user T=dovecot_lda
2024-09-09 04:04:48 1snTln-00000002pCO-24ge Completed
2024-09-09 04:04:48 1snTll-00000002pCL-3y1e => Me <my@email.com> R=detrackify_router T=detrackify
2024-09-09 04:04:48 1snTll-00000002pCL-3y1e Completed
```

Obviously there may be some differences, for example, if you don't use dovecot_lda, name of your routers, etc. but the gist of it should be very similar.

You can also open `detrackify.log` and you'll see an entry for each received email with the exim message id and any findings.

Next, look at the headers of your received email, there will be some new `X-Detrackify` headers, such as

```
X-Detrackify: Processed by Detrackify
```

If it removes tracking content, you'll see one or more entries like this:

```
X-Detrackify-Blocked: www.linkedin.com: =?utf-8?q?https=3A//www=2Elinkedin?=
    .... ?= (Size check 1x1)
```

# Thoughts

Does this mean that I'm finally free from the tracking that companies do? No, not really. Many companies leverage the fact that you like to see the styling and graphics of their email and more or less embed the tracking within. Ie, if you load that photo for the evite you got, you might very well be tracked as well.

However, it does minimize the footprint and if you do load the images, it will not load the distinct tracking items.

It's not unreasonable to try and "scramble" or even remove the parameters of some images in an attempt to further minmize the amount of tracking, but that's an exercise for a later day.

## Future improvements

- Whitelisting based on domains
- Blacklisting based on domains
- Stripping of tracking information from image URLs (you know, the ones you want to load to see the formatting), see `--stripquery` for initial steps.