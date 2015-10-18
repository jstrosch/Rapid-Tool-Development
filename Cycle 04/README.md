## PyPress - Python Script to generate cookies for WordPress 3.9

In version 3.9 of WordPress, session tokens were generated relatively weakly.  This script allows an attacker to generate all possible password fragments (covered in the video) to brute-force a session token for a site's WordPress user.

In order for this script to work, you'll need to install a WordPress version 3.9 website.  In addition, you'll need to configure a few options, which will be covered in the video.

# Demo

[YouTube Demo]()

# Dependencies

WordPress version 3.9.

# Usage

```
$ python pyPress.py
```