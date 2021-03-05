#!/usr/bin/env python
# -*- coding: utf-8 -*- #

AUTHOR = 'OmegaVoid'
SITENAME = 'OmegaVoid - Blog of Many Things'
SITEURL = ''
SITETITLE = "OmegaVoid"
SITESUBTITLE = "Blog of Many Things"
SITEDESCRIPTION= ""
SITELOGO = SITEURL + "/images/OV.png"
FAVICON = SITEURL + "/images/favicon.png"

PATH = 'content'

TIMEZONE = 'Europe/Lisbon'

DEFAULT_LANG = 'en'

# Feed generation is usually not desired when developing
#FEED_ALL_ATOM = None
#CATEGORY_FEED_ATOM = None
#TRANSLATION_FEED_ATOM = None
#AUTHOR_FEED_ATOM = None
#AUTHOR_FEED_RSS = None

#### FOR WHEN WE'RE READY TO LAUNCH
FEED_ALL_ATOM = './feeds/all.atom.xml'
#FEED_ALL_RSS = './feeds/all.rss.xml'
AUTHOR_FEED_RSS = './feeds/{slug}.rss.xml'
RSS_FEED_SUMMARY_ONLY = False

# Blogroll
# These are horrible in this theme, don't use
#LINKS = (('Tryhackme', 'https://tryhackme.com/'),
#         ('Pentesterlab', 'https://pentesterlab.com/'),
#         ('PortSwigger Academy', 'https://portswigger.net/web-security'),
#         ('These links are a great source of information if you would like to know more', '#'),)

# Social widget
SOCIAL = (('twitter', 'https://twitter.com/subitusnex'),
          ('linkedin', 'https://www.linkedin.com/in/jo%C3%A3o-zamite-20988b2a/'),
          ('github', 'https://github.com/omega-void'),
          ("rss", "./feeds/all.atom.xml"))

THM = (('https://tryhackme.com/badge/127811'))

DEFAULT_PAGINATION = 10

# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True

### Images
STATIC_PATHS = ['images']

### THEME Settings ####
THEME = "../Flex"
THEME_COLOR = 'dark'
PYGMENTS_STYLE_DARK = 'tomorrow_night'

MAIN_MENU = True
HOME_HIDE_TAGS = False

#MENU
MENUITEMS = (
    ("Rants", "/category/rants.html"),
#    ("Writeups", "/category/writeups.html"),
#    ("Tutorials", "/category/tutorials.thml"),
    ("Archives", "/archives.html"),
    ("About", "/pages/about.html")
)

#THM BADGE
BADGE = "https://tryhackme.com/badge/127811"