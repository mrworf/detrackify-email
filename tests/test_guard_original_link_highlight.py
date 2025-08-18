import jinja2
import pytest

TEMPLATES = [
    'guard_warning.html',
    'guard_warning_ar.html',
    'guard_warning_de.html',
    'guard_warning_fr.html',
    'guard_warning_es.html',
    'guard_warning_sv.html',
    'guard_warning_da.html',
    'guard_warning_zh.html',
]

@pytest.mark.parametrize('template_name', TEMPLATES)
def test_original_url_has_highlight_class(template_name):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
    template = env.get_template(template_name)
    html = template.render(
        url='https://malicious.example',
        display='https://good.example',
        domain='good.example',
        block_reason='',
        resolve=True,
        ts=0,
        sender_email=None,
        sender_display=None,
    )
    # For the new UX design, check that the main template has the new structure
    if template_name == 'guard_warning.html':
        # The new design has fixed positioning elements and state containers
        assert 'class="fixed-logo"' in html
        assert 'class="fixed-watermark"' in html
        assert 'id="checking-state"' in html
        assert 'id="safe-state"' in html
        assert 'id="unsafe-state"' in html
    else:
        # Other language templates still use the old structure
        assert 'class="url-value noselect original-url"' in html
