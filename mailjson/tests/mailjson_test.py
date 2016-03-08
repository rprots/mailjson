"""Test MailJson."""
import unittest

from contextlib import closing
from email import message_from_file
from pkg_resources import resource_stream

from mailjson import MailJson
from mailjson.mailjson import decode_value
from nose.tools import nottest
from mx.Tools.mxTools.hack import seq


@nottest
def load_mail(email_file):
    stream = resource_stream("mailjson.tests.data", email_file)
    with closing(stream) as fp:
        return message_from_file(fp)


class TestMailJson(unittest.TestCase):
    """Test MailJson Class"""

    def test_parse(self):
        """Test MailJson.parse()"""
        mj = MailJson(load_mail("1.txt"))
        data = mj.parse_mail()
        self.assertEqual(data['parsed_headers']['to'][0]['email'], "xxx-bounces@lists.xxx.com")
        self.assertEqual(data['parsed_headers']['to'][0]['name'], "")
        self.assertEqual(data['parsed_headers']['from'][0]['email'], "MAILER-DAEMON@AOL.com")
        self.assertEqual(data['parsed_headers']['from'][0]['name'], "Mail Delivery Subsystem")
        self.assertEqual(data['parsed_headers']['subject'], "Mail Delivery Problem")
        self.assertEqual(data['parsed_headers']['message-id'], "200907171908.7d834a6104831b4@omr-d25.mx.aol.com")
        self.assertNotEqual(data['parts'], [])
        self.assertEqual(data['attachments'], [])

    def test_parse_with_utf8_header(self):
        """Test MailJson.parse() test utf-8 encoded 'From' """
        mj = MailJson(load_mail("2.txt"))
        data = mj.parse_mail()
        self.assertEqual(data['parsed_headers']['from'][0]['name'], "play.pl")

    def test_parse_with_utf8_subject(self):
        """Test MailJson.parse() test utf-8 encoded 'Subject' """
        mj = MailJson(load_mail("3.txt"))
        subj = ("\xd0\x92\xd0\xb0\xd1\x88\xd0\xb5 \xd1\x81\xd0\xbe\xd0\xbe"
                "\xd0\xb1\xd1\x89\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5 \xd0\xbd"
                "\xd0\xb5 \xd0\xb4\xd0\xbe\xd1\x81\xd1\x82\xd0\xb0\xd0\xb2"
                "\xd0\xbb\xd0\xb5\xd0\xbd\xd0\xbe. Mail failure.")
        data = mj.parse_mail()
        self.assertEqual(data['parsed_headers']['subject'], subj)

    def test_parse_with_subject_encoding(self):
        """Test MailJson.parse() test 'Subject' encoding """
        mj = MailJson(load_mail("3.txt"))
        subj = ("\xd0\x92\xd0\xb0\xd1\x88\xd0\xb5 \xd1\x81\xd0\xbe\xd0\xbe"
                "\xd0\xb1\xd1\x89\xd0\xb5\xd0\xbd\xd0\xb8\xd0\xb5 \xd0\xbd"
                "\xd0\xb5 \xd0\xb4\xd0\xbe\xd1\x81\xd1\x82\xd0\xb0\xd0\xb2"
                "\xd0\xbb\xd0\xb5\xd0\xbd\xd0\xbe. Mail failure.")
        data = mj.parse_mail()
        self.assertEqual(data['parsed_headers']['subject'], subj)

        mj = MailJson(load_mail("4.txt"))
        subj = 'Sie haben die Mailingliste "newsletter" abbestellt'
        data = mj.parse_mail()
        self.assertEqual(data['parsed_headers']['subject'], subj)

    def test__fix_encoded_subject(self):
        """Test MailJson._fix_encoded_subject()"""
        ret = MailJson()._fix_encoded_subject("A")
        self.assertEqual(ret, "A")
        ret = MailJson()._fix_encoded_subject("AAAAAAAA")
        self.assertEqual(ret, "AAAAAAAA")
        ret = MailJson()._fix_encoded_subject("AAAAAAAA\nBB")
        self.assertEqual(ret, "AAAAAAAA\nBB")
        subj1 = ("=?iso-8859-1?q?Sie_haben_die_Mailingliste_=22newsletter"
                 "=22_ab?=\r\n =?iso-8859-1?q?bestellt?=")
        subj2 = ("=?iso-8859-1?q?Sie_haben_die_Mailingliste_=22newsletter"
                 "=22_ab?=\n =?iso-8859-1?q?bestellt?=")
        subj2 = MailJson()._fix_encoded_subject(subj1)
        self.assertEqual(subj2, subj2)

    def test__extract_recipient(self):
        """Test MailJson._extract_recipient()"""
        header = "=?koi8-r?B?78vTwc7BIOvP18HM2N7Vyw==?= <xxxxxx@gmail.com>"
        name1 = "\xef\xcb\xd3\xc1\xce\xc1 \xeb\xcf\xd7\xc1\xcc\xd8\xde\xd5\xcb"
        email1 = "xxxxxx@gmail.com"
        (name, email) = MailJson()._extract_recipient(header)
        self.assertEqual(name, name1)
        self.assertEqual(email, email1)

        header = "'Vitush' <zzz@gmail.com>"
        (name, email) = MailJson()._extract_recipient(header)
        self.assertEqual(name, "Vitush")
        self.assertEqual(email, "zzz@gmail.com")

        header = "AAA BBB"
        (name, email) = MailJson()._extract_recipient(header)
        self.assertEqual(name, "AAA")
        self.assertEqual(email, None)

    def test__extract_email(self):
        """Test MailJson._extract_email()"""
        email = MailJson()._extract_email("<user@doman.com>")
        self.assertEqual(email, "user@doman.com")
        email = MailJson()._extract_email("<user.doman.com>")
        self.assertEqual(email, None)

    def test_parse_with_attachments(self):
        """Test MailJson.parse() with attachments"""
        mail = load_mail("5.txt")
        mj = MailJson(mail)
        mj.include_parts = False
        mj.include_attachments = True
        data = mj.parse_mail()
        attachment_content = data['attachments'][0]['content']
        content_begin = 'iVBORw0KGgoAAAANSUhEUgAAAvoAAAD8CAYAAAAG2QDhAABAAElE'
        self.assertTrue(attachment_content.startswith(content_begin))

    def test_parse_with_parts(self):
        """Test MailJson.parse() with parts"""
        mail = load_mail("5.txt")
        mj = MailJson(mail)
        mj.include_parts = True
        mj.include_attachments = False
        data = mj.parse_mail()
        part_content = data['parts'][0]['content']
        content_begin = '*GDG DevFest 2014'
        self.assertTrue(part_content.startswith(content_begin))

    def test_parse_with_filters(self):
        """Test MailJson.parse() with filters"""
        mail = load_mail("2.txt")
        mj = MailJson(mail)
        mj.include_parts = False
        data = mj.parse_mail()
        with self.assertRaises(KeyError):
            p = data['parts']

        mj = MailJson(load_mail("5.txt"))
        mj.include_attachments = False
        data = mj.parse_mail()
        with self.assertRaises(KeyError):
            a = data['attachments']

        mj = MailJson(mail)
        mj.include_headers = ("to",)
        data = mj.parse_mail()
        self.assertEqual(data['headers']['to'], '<vitush.dev@gmail.com>')
        self.assertEqual(data['parsed_headers']['to'][0]['email'], "vitush.dev@gmail.com")
        with self.assertRaises(KeyError):
            f = data['headers']['from']
