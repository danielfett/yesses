from yesses.module import YTest
from yesses.scan.information_leakage import InformationLeakage


def test_information_leakage():
    inputs = """
      - scan Information Leakage:
          pages: 
            - url: page0
              data: "<!-- test@example.com /var/home/bla --><html>\n\n<head><script src='ajkldfjalk'></script></head>\n\n <body>\n\n<!-- This is a comment --><h1>Title</h1>\n\n<!-- secret.txt \n\n/1x23/ex234--><p>Text with path /home/user/secret/key.pub</p> <a href='/docs/'>Website</a> <label>192.168.2.196 /usr/share/docs/ajdlkf/adjfl</label>\n\n<style> test@example.com </style>\n\n</body>"
            - url: page1
              data: "<html><script>// This is a js comment 192.168.170.128\n\nfunction {return 'Hello World';}\n\n</script><body></body><script>// Comment two with email@example.com \n\n console.log('test')/* Comment over\n\n several lines\n\n*/</script></html>\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
            - url: page2
              data: "/*! modernizr 3.6.0 (Custom Build) | MIT *\n\n* https://modernizr.com/download/?-svgclippaths-setclasses !*/ \n\n!function(e,n,s){function o(e) // Comment three\n\n{var n=f.className,s=Modernizr._con /* Last \n\n multi \n\n line \n\n comment */ flakjdlfjldjfl\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
        find:
          - Leakages
    """
    expected = {'Leakages': [{'url': 'page0', 'type': 'ip', 'found': 'visible_text', 'finding': ' 192.168.2.196 '},
                {'url': 'page0', 'type': 'path', 'found': 'visible_text', 'finding': ' /home/user/secret/key.pub '},
                {'url': 'page0', 'type': 'path', 'found': 'visible_text', 'finding': ' /usr/share/docs/ajdlkf/adjfl\n'},
                {'url': 'page1', 'type': 'ip', 'found': 'css_js_comment', 'finding': ' 192.168.170.128'},
                {'url': 'page1', 'type': 'email', 'found': 'css_js_comment', 'finding': ' email@example.com'}]}
    test = YTest(inputs)
    result = test.run()
    assert result == expected
