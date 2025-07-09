#!/usr/bin/env python3
"""Unit tests for domain matching utility functions in guard/utils.py."""

import os
import sys
import unittest

# Add the parent directory to the path so we can import guard modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from guard.utils import GuardUtils


class TestGuardUtilsDomainMatching(unittest.TestCase):
    """Test the domain matching utility functions."""

    def test_normalize_domain(self):
        """Test domain normalization."""
        # Test basic normalization
        self.assertEqual(GuardUtils.normalize_domain('EXAMPLE.COM'), 'example.com')
        self.assertEqual(GuardUtils.normalize_domain('  Test.Domain  '), 'test.domain')
        self.assertEqual(GuardUtils.normalize_domain('team.talkspace.com'), 'team.talkspace.com')
        
        # Test edge cases
        self.assertEqual(GuardUtils.normalize_domain(''), '')
        self.assertEqual(GuardUtils.normalize_domain(None), '')
        self.assertEqual(GuardUtils.normalize_domain('   '), '')

    def test_is_subdomain(self):
        """Test subdomain detection."""
        # Test same domain
        self.assertTrue(GuardUtils.is_subdomain('example.com', 'example.com'))
        self.assertTrue(GuardUtils.is_subdomain('TEAM.TALKSPACE.COM', 'team.talkspace.com'))
        
        # Test subdomain relationships
        self.assertTrue(GuardUtils.is_subdomain('sub.example.com', 'example.com'))
        self.assertTrue(GuardUtils.is_subdomain('deep.sub.example.com', 'example.com'))
        self.assertTrue(GuardUtils.is_subdomain('deep.sub.example.com', 'sub.example.com'))
        
        # Test reverse relationships (should not be subdomain)
        self.assertFalse(GuardUtils.is_subdomain('example.com', 'sub.example.com'))
        self.assertFalse(GuardUtils.is_subdomain('sub.example.com', 'deep.sub.example.com'))
        
        # Test different domains
        self.assertFalse(GuardUtils.is_subdomain('team.talkspace.com', 'try.talkspace.com'))
        self.assertFalse(GuardUtils.is_subdomain('mail.google.com', 'drive.google.com'))
        
        # Test edge cases
        self.assertFalse(GuardUtils.is_subdomain('', 'example.com'))
        self.assertFalse(GuardUtils.is_subdomain('example.com', ''))
        self.assertFalse(GuardUtils.is_subdomain('', ''))
        self.assertFalse(GuardUtils.is_subdomain(None, 'example.com'))
        self.assertFalse(GuardUtils.is_subdomain('example.com', None))

    def test_share_parent_domain(self):
        """Test parent domain sharing detection."""
        # Test same domain
        self.assertTrue(GuardUtils.share_parent_domain('example.com', 'example.com'))
        self.assertTrue(GuardUtils.share_parent_domain('TEAM.TALKSPACE.COM', 'team.talkspace.com'))
        
        # Test domains with same parent
        self.assertTrue(GuardUtils.share_parent_domain('team.talkspace.com', 'try.talkspace.com'))
        self.assertTrue(GuardUtils.share_parent_domain('mail.google.com', 'drive.google.com'))
        self.assertTrue(GuardUtils.share_parent_domain('www.example.com', 'api.example.com'))
        self.assertTrue(GuardUtils.share_parent_domain('sub1.example.org', 'sub2.example.org'))
        
        # Test domains with different parents
        self.assertFalse(GuardUtils.share_parent_domain('team.talkspace.com', 'mail.google.com'))
        self.assertFalse(GuardUtils.share_parent_domain('example.com', 'other.com'))
        self.assertFalse(GuardUtils.share_parent_domain('example.com', 'example.org'))
        
        # Test subdomain relationships (should share parent domain)
        self.assertTrue(GuardUtils.share_parent_domain('sub.example.com', 'example.com'))
        self.assertTrue(GuardUtils.share_parent_domain('example.com', 'sub.example.com'))
        
        # Test domains with different numbers of levels (but same parent)
        self.assertTrue(GuardUtils.share_parent_domain('example.com', 'sub.example.com'))
        self.assertTrue(GuardUtils.share_parent_domain('sub.example.com', 'example.com'))
        
        # Test very long subdomains
        self.assertTrue(GuardUtils.share_parent_domain('very.deep.sub.example.com', 'another.deep.sub.example.com'))
        
        # Test case sensitivity
        self.assertTrue(GuardUtils.share_parent_domain('TEAM.TALKSPACE.COM', 'try.talkspace.com'))
        self.assertTrue(GuardUtils.share_parent_domain('team.talkspace.com', 'TRY.TALKSPACE.COM'))
        
        # Test domains with extra whitespace
        self.assertTrue(GuardUtils.share_parent_domain(' team.talkspace.com ', 'try.talkspace.com'))
        self.assertTrue(GuardUtils.share_parent_domain('team.talkspace.com', ' try.talkspace.com '))
        
        # Test edge cases
        self.assertFalse(GuardUtils.share_parent_domain('', 'example.com'))
        self.assertFalse(GuardUtils.share_parent_domain('example.com', ''))
        self.assertFalse(GuardUtils.share_parent_domain('', ''))
        self.assertFalse(GuardUtils.share_parent_domain(None, 'example.com'))
        self.assertFalse(GuardUtils.share_parent_domain('example.com', None))
        
        # Test domains with less than 2 parts
        self.assertFalse(GuardUtils.share_parent_domain('com', 'org'))
        self.assertFalse(GuardUtils.share_parent_domain('example', 'other'))

    def test_comprehensive_domain_matching_scenarios(self):
        """Test comprehensive real-world domain matching scenarios."""
        # Test cases that should match (same parent domain)
        positive_cases = [
            # Talkspace case that was broken
            ('team.talkspace.com', 'try.talkspace.com'),
            ('mail.talkspace.com', 'support.talkspace.com'),
            ('www.talkspace.com', 'api.talkspace.com'),
            
            # Google domains
            ('mail.google.com', 'drive.google.com'),
            ('docs.google.com', 'calendar.google.com'),
            ('www.google.com', 'api.google.com'),
            ('maps.google.com', 'translate.google.com'),
            
            # Microsoft domains
            ('outlook.live.com', 'onedrive.live.com'),
            ('mail.microsoft.com', 'support.microsoft.com'),
            ('www.microsoft.com', 'docs.microsoft.com'),
            
            # Example domains
            ('www.example.com', 'api.example.com'),
            ('mail.example.org', 'support.example.org'),
            ('sub1.example.net', 'sub2.example.net'),
            ('dev.example.co.uk', 'prod.example.co.uk'),
            
            # Single-level domains (should match themselves)
            ('example.com', 'example.com'),
            ('google.com', 'google.com'),
            ('talkspace.com', 'talkspace.com'),
        ]
        
        for domain1, domain2 in positive_cases:
            with self.subTest(domain1=domain1, domain2=domain2):
                self.assertTrue(
                    GuardUtils.share_parent_domain(domain1, domain2),
                    f"Expected {domain1} and {domain2} to share parent domain"
                )
        
        # Test cases that should NOT match (different parent domains)
        negative_cases = [
            # Different companies
            ('team.talkspace.com', 'mail.google.com'),
            ('example.com', 'other.com'),
            ('google.com', 'microsoft.com'),
            ('talkspace.com', 'amazon.com'),
            
            # Different TLDs
            ('example.com', 'example.org'),
            ('google.com', 'google.net'),
            ('talkspace.com', 'talkspace.org'),
            ('example.co.uk', 'example.com'),
            
            # Different second-level domains
            ('team.talkspace.com', 'team.otherspace.com'),
            ('mail.google.com', 'mail.gmail.com'),
            ('www.example.com', 'www.example2.com'),
            ('api.example.com', 'api.example.org'),
            
            # Subdomain relationships (should share parent domain)
            # Note: These are actually covered by the subdomain logic, not parent domain logic
            # but they should still match
        ]
        
        for domain1, domain2 in negative_cases:
            with self.subTest(domain1=domain1, domain2=domain2):
                self.assertFalse(
                    GuardUtils.share_parent_domain(domain1, domain2),
                    f"Expected {domain1} and {domain2} NOT to share parent domain"
                )

    def test_edge_cases_and_error_handling(self):
        """Test edge cases and error handling in domain matching."""
        # Test invalid domains
        invalid_domains = [
            '', None, '   ', 'invalid', 'too.many.dots.in.this.domain.com',
            'domain-with-dashes.com', 'domain_with_underscores.com',
            'domain.with.multiple..dots.com', '.domain.com', 'domain.',
            'domain..com', 'domain.com.', '.domain.com.'
        ]
        
        for invalid_domain in invalid_domains:
            with self.subTest(invalid_domain=invalid_domain):
                # Should handle gracefully without raising exceptions
                try:
                    result = GuardUtils.share_parent_domain(invalid_domain, 'example.com')
                    # Should return False for invalid domains
                    self.assertFalse(result)
                except Exception as e:
                    self.fail(f"share_parent_domain raised exception for {invalid_domain}: {e}")
                
                try:
                    result = GuardUtils.share_parent_domain('example.com', invalid_domain)
                    # Should return False for invalid domains
                    self.assertFalse(result)
                except Exception as e:
                    self.fail(f"share_parent_domain raised exception for {invalid_domain}: {e}")

    def test_performance_edge_cases(self):
        """Test performance edge cases with very long domains."""
        # Test very long subdomains
        long_domain1 = 'a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com'
        long_domain2 = '1.2.3.4.5.6.7.8.9.0.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.example.com'
        
        self.assertTrue(GuardUtils.share_parent_domain(long_domain1, long_domain2))
        
        # Test domains with many parts
        many_parts1 = '.'.join(['part' + str(i) for i in range(100)]) + '.example.com'
        many_parts2 = '.'.join(['other' + str(i) for i in range(100)]) + '.example.com'
        
        self.assertTrue(GuardUtils.share_parent_domain(many_parts1, many_parts2))


if __name__ == '__main__':
    unittest.main() 