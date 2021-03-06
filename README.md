# MailJson

This is a fork of MailToJson, that is released under [MIT license](https://github.com/Newsman/MailToJson/blob/master/LICENSE) by [Newsman App - Smart Email Service Provider](https://www.newsmanapp.com).

## How to use

The MailJson class will try to figure out which datatype it is initialized with, and do the correct conversion based that. The plan is that both the JSON-data and the message as an email.message.Message-object will be available through this class.

**NOTE**: The conversion from JSON to an email-object is not yet done.

Example usage:
```python
from MailJson import MailJson
m = <email.message.Message object>
mj = MailJson(m)
data = mj.parse_mail()
```

```python
from MailJson import MailJson
m = <email.message.Message object>
mj = MailJson(m, encoding="utf-8")
headers = ("subject", "from", "to", "date", "message-id", "date")
mj.include_headers=headers     # In case you are only interested in specific headers, not all.
mj.include_parts=False         # In case you are not interested in parsing mail parts.
mj.include_attachments=False   # In case you are not interested in parsing attachments.
data = mj.parse_mail()
```


## JSON Format

```yaml
json:
  encoding: "utf-8"
  headers:
    header_key1: value
    header_key2: value
  parsed_headers:
    subject: "The email subject as utf-8 string"
    date: "2015-03-17 17:48:06"
    from:
      - { name: "Sender Name", email: "sender@email.com" }
    to:
      - { name: "Recipient Name", email: "recipient@email.com" }
      - { name: "Recipient Name 2", email: "recipient2@email.com" }
    cc:
      - { name: "Recipient Name", email: "recipient@email.com" }
      - { name: "Recipient Name 2", email: "recipient2@email.com" }
  parts:
    - { content_type: "text/plain", content: "body of this part", "headers": { "header_key1": value, "header_key2": value } }
    - { content_type: "text/html", content: "body of this part", "headers": { "header_key1": value, "header_key2": value } }
  attachments:
    - { filename": "invoice.pdf", content_type: "application/pdf", content: "base64 of binary data" }
    - { filename": "invoice2.pdf", content_type: "application/pdf", content: "base64 of binary data" }
```

# History

Version 1.4.8:

- 2016-09-08: Changed version to 1.4.8 to be older then previous release. 

Version 0.2.2:

- 2016-01-11: Changed the way how package __version__ is defined.

Version 0.2.0:

- 2016-01-03: Added 'parsed_headers' section. Added encoding support. Improved filters.

Version 0.1.1:

- 2015-12-24: Added tests.

Version 0.1.0:

- 2015-12-23: Fixed encoding parsing in "From", "To", "Cc".
- 2015-12-22: Renamed variables to achieve PEP8.
- 2015-12-22: Re-factored filters.
- 2015-12-21: Added setup.py.
- 2015-12-18: Added python2.7 compatibility.
- 2015-12-18: Added filters.
- 2015-12-18: Fixed double encoding.
- 2015-12-18: Forked from https://github.com/eigir/MailJson

# License

This code is released under [MIT license](https://github.com/Newsman/MailToJson/blob/master/LICENSE)
