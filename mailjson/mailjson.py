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
import datetime
import email
import re
import sys


##### Python 2.7 compatibility.
if sys.version_info < (3,):
    from email import Header as email_header

else:
    from email import header as email_header

    def unicode(value, encoding='utf-8', errors='strict'):
        """Convert to unicode"""
        return str(value, encoding, errors)

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


def _get_encoding(string):
    """Get string encoding"""
    if isinstance(string, str):
        return 'ascii'
    else:
        return chardet.detect(string)['encoding']

def decode_value(header_value, encoding):
    """Decode header value"""
    encoding = encoding.lower() if encoding else "ascii"
    if _get_encoding(header_value) == encoding:
        # Do not encode second time.
        return header_value
    header_value = unicode(header_value, encoding).strip().strip("\t")
    return header_value.encode(encoding)


class MailJson(object):
    """Class to convert between json and mail format"""

    def __init__(self, data=None):
        self.encoding = "utf-8"
        self.raw_parts = []
        self.include_headers = ()
        self.include_parts = True
        self.include_attachents = True

        if data:
            if isinstance(data, email.message.Message):
                self.mail = data
                self.json_data = {}
            elif type(data) is dict:
                raise NotImplementedError('Conversion from JSON to mail,'
                                          ' is not yet implemented')
                # TODO: Convert json to email.message.Message object
            else:
                raise TypeError('Unknown data-type passed')

    @staticmethod
    def _decode_headers(headers):
        """Decode headers"""
        if type(headers) is not list:
            headers = [headers]

        ret = []
        for header in headers:
            header = email_header.decode_header(header)
            h_ret = []
            for (value, encoding) in header:
                decoded_hv = decode_value(value, encoding)
                h_ret.append(decoded_hv)
            if len(h_ret) == 1:
                h_ret = h_ret[0]
            ret.append(h_ret)
        return ret

    def _get_part_headers(self, part):
        """Get headers from message part"""
        # raw headers
        headers = {}
        for h_key in part.keys():
            if self.include_headers and \
                not h_key.lower() in self.include_headers:
                continue
            h_key = h_key.lower()
            h_value = part.get_all(h_key)
            h_value = self._decode_headers(h_value)

            headers[h_key] = h_value[0] if len(h_value) == 1 else h_value
        return headers

    @staticmethod
    def _parse_date(string):
        """Parse date"""
        if string is None:
            return datetime.datetime.now()
        time_tuple = email.utils.parsedate_tz(string)
        if time_tuple is None:
            return datetime.datetime.now()
        timestamp = email.utils.mktime_tz(time_tuple)
        date = datetime.datetime.fromtimestamp(timestamp)
        return date

    @staticmethod
    def _fix_encoded_subject(subject):
        """Convert encoded multi-line subject to one line"""
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
        """Extract email address from string"""
        ret = EMAIL_EXTRACT_RE.findall(string)
        if len(ret) < 1:
            parts = string.split(" ")
            for string_part in parts:
                string_part = string_part.strip()
                if EMAIL_RE.match(string_part):
                    return string_part
            return None
        else:
            return ret[0][0]

    def _get_recipient_list(self, header):
        """Get list of recipients from header by name"""
        rcpts = self.mail.get_all(header, None)
        if not rcpts:
            return None
        if isinstance(rcpts, list):
            rcpts = ",".join(rcpts)
        # Get list of recipients
        rcpts = rcpts.replace("\n", " ").replace("\r", " ").strip()
        return rcpts.split(',')

    def _extract_recipient(self, header):
        """Extract recipient name and email address from header"""
        v_list = email_header.decode_header(header)
        if len(v_list) == 2:
            # User name and Email already split.
            name = v_list[0][0]
            address = str(v_list[1][0])
            address = address.replace("<", "").replace(">", "").strip()
            return (name, address)
        else:
            entry = v_list[0][0].strip()
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

            #Remove " and ' around name.
            name = entry.replace('"', '').replace("'", "").strip()
            address = self._extract_email(address).strip()
            #name = entry
            return (name, address)
        return (None, None)

    def _parse_recipients(self, header):
        """Parse header and find all recipients"""
        ret = []
        rcpt_list = self._get_recipient_list(header)
        if not rcpt_list:
            return []
        for rcpt in rcpt_list:
            (name, address) = self._extract_recipient(rcpt)
            ret.append({"name": name, "email": address})
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

        self.json_data["from"] = self._parse_recipients("from")
        self.json_data["to"] = self._parse_recipients("to")
        self.json_data["cc"] = self._parse_recipients("cc")
        self.json_data["bcc"] = self._parse_recipients("bcc")

        attachments = []
        parts = []
        for part in msg.walk():
            if part.is_multipart():
                continue

            content_disposition = part.get("Content-Disposition", None)
            if content_disposition:
                # We have attachment
                if not self.include_attachents:
                    # We are not interested in parsed attachments.
                    continue
                found = FILENAME_RE.findall(content_disposition)
                if found:
                    filename = sorted(found[0])[1]
                else:
                    filename = "undefined"

                json_attachment = {"filename": filename,
                                   "content": base64.b64encode(
                                                part.get_payload(decode=True)),
                                   "content_type": part.get_content_type()}
                attachments.append(json_attachment)
            else:
                if not self.include_parts:
                    # We are not interested in parsed parts.
                    continue
                try:
                    charset = self._get_content_charset(part, "utf-8").decode()
                    json_part = {"content_type": part.get_content_type(),
                                 "content": unicode(part.get_payload(decode=1),
                                                    charset,
                                                    "ignore"
                                                    ).encode(self.encoding),
                                 "headers": self._get_part_headers(part)}
                    parts.append(json_part)
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
