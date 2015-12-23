"""Mail to JSON converter."""
# ---------------------------------------------------------------------
#  (c) 2013 Newsman App, https://github.com/Newsman/MailToJson
#  (c) 2015 Mike Andersen, mike@geekpod.net
#  (c) 2015 Andriy Vitushynskyy, vitush.dev@gmail.com
#
#  This code is released under MIT license.
# ---------------------------------------------------------------------

import base64
import chardet
import csv
import datetime
import email
import re
import sys

from io import StringIO

##### Python 2.7 compatibility.
if sys.version_info < (3,):
    from email import Header as email_header

    def csv_next(csv_obj):
        return csv_obj.next()

    def decode_value(value, encoding):
        encoding = encoding.lower() if encoding else "ascii"
        value = unicode(value, encoding).strip().strip("\t")
        return value.encode(encoding)

    def get_encoding(string):
        encoding = chardet.detect(string)
        return encoding['encoding']

else:
    from email import header as email_header

    def unicode(value, encoding='utf-8', errors='strict'):
        return str(value, encoding, errors)

    def csv_next(csv_obj):
        return csv_obj.__next__()

    def decode_value(value, encoding):
        if get_encoding(value) == encoding:
            # Do not encode second time.
            return value
        value = str(value).strip().strip("\t")
        return value.encode(encoding)

    def get_encoding(string):
        if isinstance(string, str):
            return 'ascii'
        else:
            encoding = chardet.detect(string)
            return encoding['encoding']

###########################################################################

# Regular expression from
#  https://github.com/django/django/blob/master/django/core/validators.py

EMAIL_RE = re.compile(
    # dot-atom
    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"
    # quoted-string, see also http://tools.ietf.org/html/rfc2822#section-3.2.5
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]'
        r'|\\[\001-\011\013\014\016-\177])*"'
    # domain part
    r')@((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+'
        r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)$)'
    r'|\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)'
        r'(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$', re.IGNORECASE)

EMAIL_EXTRACT_RE = re.compile(
    r"<(([.0-9a-z_+-=]+)@(([0-9a-z-]+\.)+[0-9a-z]{2,9}))>", re.M | re.S | re.I)
FILENAME_RE = re.compile(
    r"filename=\"(.+)\"|filename=([^;\n\r\"\']+)", re.I | re.S)

BEGIN_TAB_RE = re.compile(r"^\t+", re.M)
BEGIN_SPACE_RE = re.compile(r"^\s+", re.M)


class MailJson(object):
    """Class to convert between json and mail format"""

    def __init__(self, d):
        self.encoding = "utf-8"
        self.raw_parts = []
        self.include_headers = ()
        self.include_parts = True
        self.include_attachents = True

        if isinstance(d, email.message.Message):
            self.mail = d
            self.json_data = {}
        elif type(d) is dict:
            raise NotImplementedError('Conversion from JSON to mail,'
                                      ' is not yet implemented')
            # TODO: Convert json to email.message.Message object
        else:
            raise TypeError('Unknown data-type passed')

    def _decode_headers(self, headers):
        if type(headers) is not list:
            headers = [headers]

        ret = []
        for header in headers:
            header = email_header.decode_header(header)
            h_ret = []
            for h_decoded in header:
                header_value = h_decoded[0]
                decoded_hv = decode_value(header_value, self.encoding)
                h_ret.append(decoded_hv)
            if len(h_ret) == 1:
                h_ret = h_ret[0]
            ret.append(h_ret)
        return ret

    def _get_part_headers(self, part):
        # raw headers
        headers = {}
        for h_key in part.keys():
            if self.include_headers and \
                not h_key.lower() in self.include_headers:
                continue
            h_key = h_key.lower()
            h_value_list = part.get_all(h_key)
            h_value_list = self._decode_headers(h_value_list)

            if len(h_value_list) == 1:
                headers[h_key] = h_value_list[0]
            else:
                headers[h_key] = h_value_list
        return headers

    @staticmethod
    def _parse_date(string):
        if string is None:
            return datetime.datetime.now()
        string = unicode(string, 'ascii')
        time_tuple = email.utils.parsedate_tz(string)
        if time_tuple is None:
            return datetime.datetime.now()
        timestamp = email.utils.mktime_tz(time_tuple)
        date = datetime.datetime.fromtimestamp(timestamp)
        return date

    @staticmethod
    def _fix_encoded_subject(subject):
        if subject is None:
            return ""
        subject = "%s" % subject
        subject = subject.strip()

        if len(subject) < 2:
            # empty string or not encoded string ?
            return subject
        if subject.find("\n") == -1:
            # is on single line
            return subject
        if subject[0:2] != "=?":
            # not encoded
            return subject

        subject = subject.replace("\r", "")
        subject = BEGIN_TAB_RE.sub("", subject)
        subject = BEGIN_SPACE_RE.sub("", subject)
        lines = subject.split("\n")

        new_subject = ""
        for line in lines:
            new_subject = "%s%s" % (new_subject, line)
            if line[-1] == "=":
                new_subject = "%s\n " % new_subject
        return new_subject

    @staticmethod
    def _extract_email(string):
        ret = EMAIL_EXTRACT_RE.findall(string)
        if len(ret) < 1:
            parts = string.split(" ")
            for email_part in parts:
                email_part = email_part.strip()
                if EMAIL_RE.match(email_part):
                    return email_part
            return None
        else:
            return ret[0][0]

    def _parse_recipients(self, value):
        if value is None:
            return None
        ret = []

        # Sometimes a list is passed, which breaks .replace()
        if isinstance(value, list):
            value = b",".join(value)
        value = unicode(value, 'UTF8')
        value = value.replace("\n", " ").replace("\r", " ").strip()
        csv_obj = csv.reader(StringIO(value))
        try:
            row = csv_next(csv_obj)
        except StopIteration:
            return ret

        for entry in row:
            entry = entry.strip()
            if EMAIL_RE.match(entry):
                address = entry
                entry = ""
            else:
                address = self._extract_email(entry)
                entry = entry.replace("<%s>" % address, "")
                entry = entry.strip()
                if address and entry.find(address) != -1:
                    entry = entry.replace(address, "").strip()
            # If all else has failed
            if entry and address is None:
                e_split = entry.split(" ")
                address = e_split[-1].replace("<", "").replace(">", "")
                entry = " ".join(e_split[:-1])

            ret.append({"name": entry, "email": address})
        return ret

    @staticmethod
    def _get_content_charset(part, failobj=None):
        """Return the charset parameter of the Content-Type header.

        The returned string is always coerced to lower case.  If there is no
        Content-Type header, or if that header has no charset parameter,
        failobj is returned.
        """
        missing = object()
        charset = part.get_param("charset", missing)
        if charset is missing:
            return failobj
        if isinstance(charset, tuple):
            # RFC 2231 encoded, so decode it, and it better end up as ascii.
            pcharset = charset[0] or "us-ascii"
            try:
                # LookupError will be raised if the charset isn't known to
                # Python.  UnicodeError will be raised if the encoded text
                # contains a character not in the charset.
                charset = str(charset[2], pcharset).encode("us-ascii")
            except (LookupError, UnicodeError):
                charset = charset[2]
        # charset character must be in us-ascii range
        try:
            if isinstance(charset, str):
                charset = charset.encode("us-ascii")
            charset = unicode(charset, "us-ascii").encode("us-ascii")
        except UnicodeError:
            return failobj
        # RFC 2046, $4.1.2 says charsets are not case sensitive
        return charset.lower()

    def parse_mail(self, msg):
        """Parse mail"""

        headers = self._get_part_headers(msg)
        self.json_data["headers"] = headers
        self.json_data["datetime"] = self._parse_date(
                headers.get("date", None)).strftime("%Y-%m-%d %H:%M:%S")
        self.json_data["subject"] = self._fix_encoded_subject(
                headers.get("subject", None))
        self.json_data["to"] = self._parse_recipients(
                headers.get("to", None))
        self.json_data["from"] = self._parse_recipients(
                headers.get("from", None))
        self.json_data["cc"] = self._parse_recipients(
                headers.get("cc", None))

        attachments = []
        parts = []
        for part in msg.walk():
            if part.is_multipart():
                continue

            content_disposition = part.get("Content-Disposition", None)
            if content_disposition:
                # we have attachment
                if self.include_attachents:
                    found = FILENAME_RE.findall(content_disposition)
                    if found:
                        filename = sorted(found[0])[1]
                    else:
                        filename = "undefined"

                    attach = {"filename": filename,
                              "content": base64.b64encode(
                                        part.get_payload(decode=True)),
                              "content_type": part.get_content_type()}
                    attachments.append(attach)
            else:
                if self.include_parts:
                    try:
                        charset = self._get_content_charset(
                                        part, "utf-8").decode()
                        parsed_part = {"content_type": part.get_content_type(),
                                       "content": unicode(
                                                    part.get_payload(decode=1),
                                                    charset,
                                                    "ignore"
                                                    ).encode(self.encoding),
                             "headers": self._get_part_headers(part)}
                        parts.append(parsed_part)
                        self.raw_parts.append(part)
                    except LookupError:
                        # Sometimes an encoding isn't recognized.
                        # Not much to be done.
                        pass

        if self.include_attachents:
            self.json_data["attachments"] = attachments
        if self.include_parts:
            self.json_data["parts"] = parts
        self.json_data["encoding"] = self.encoding

        return self.json_data
