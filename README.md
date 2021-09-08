Yara Python ICAP Server 
=====================
An ICAP Server with yara scanner for URL and content.

## Requirement
* Squid Proxy 3.5
* Python 3

## Squid Configuration
```
icap_enable on
icap_preview_enable off
icap_send_client_ip on
icap_send_client_username on
icap_service service_resp respmod_precache bypass=1 icap://127.0.0.1:1344/yara
adaptation_access service_resp allow all
```

## Running
```
$ git clone https://github.com/RamadhanAmizudin/python-icap-yara
$ pip install -r requirements.txt
$ python server.py
```

## Config File
```
[config]
content_rules = <full path to rules>
url_rules = <full path to rules>
content_dir = <directory where data will be stored>
```

## Log Content
```
{
    "content": "<hex of content>",
    "request_header": {
        "accept": [
            "*/*"
        ],
        "host": [
            "blog.honeynet.org.my"
        ],
        "user-agent": [
            "curl/7.47.0"
        ]
    },
    "response_header": {
        "content-type": [
            "text/html; charset=UTF-8"
        ],
        "date": [
            "Mon, 06 Feb 2017 15:55:31 GMT"
        ],
        "link": [
            "<http://blog.honeynet.org.my/wp-json/>; rel=\"https://api.w.org/\"",
            "<http://wp.me/6OPJo>; rel=shortlink"
        ],
        "server": [
            "Apache/2.2.22 (Ubuntu)"
        ],
        "vary": [
            "Accept-Encoding"
        ]
    },
    "rules": [
        "list of rules triggered"
    ]
}
```

License
=======
The MIT License (MIT)

Copyright (c) 2021 Ahmad Ramadhan Amizudin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Questions & Comments
=====================
If you encounter a bug, please feel free to post it on GitHub. For questions or comments.
