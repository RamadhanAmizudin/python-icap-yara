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

Questions & Comments
=====================
If you encounter a bug, please feel free to post it on GitHub. For questions or comments.
