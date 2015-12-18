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
mj = MailJson(m)
headers = ("subject", "from", "to", "date", "message-id", "date")
mj.set_filters(include_parts=False, include_attachments=False, include_headers=headers)
data = mj.parse_mail()
```


## JSON Format

```yaml
json:
  headers:
    header_key1: value
    header_key2: value
  subject: "The email subject as utf-8 string"
  datetime: "2015-03-17 17:48:06"
  encoding: "utf-8"
  from:
    - { name: "Sender Name", email: "sender@email.com" }
  to:
    - { name: "Recipient Name", email: "recpient@email.com" }
    - { name: "Recipient Name 2", email: "recpient2@email.com" }
  cc:
    - { name: "Recipient Name", email: "recpient@email.com" }
    - { name: "Recipient Name 2", email: "recpient2@email.com" }
  parts:
    - { content_type: "text/plain", content: "body of this part", "headers": { "header_key1": value, "header_key2": value } }
    - { content_type: "text/html", content: "body of this part", "headers": { "header_key1": value, "header_key2": value } }
  attachments:
    - { filename": "invoice.pdf", content_type: "application/pdf", content: "base64 of binary data" }
    - { filename": "invoice2.pdf", content_type: "application/pdf", content: "base64 of binary data" }
```

# History

2015-11-19: Forked MailToJson, renamed MailToJson to MailJson and added my changes.

2015-12-18: Added python2.7 compatibility. Added filters. Fixed double encoding.

# License

This code is released under [MIT license](https://github.com/Newsman/MailToJson/blob/master/LICENSE)
