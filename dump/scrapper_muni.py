import scrapy
import re
import logging
from urlparse import urlparse
import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor
from scrapy.linkextractors import LinkExtractor
from scrapy import signals
from scrapy.http import Request
from scrapy.utils.httpobj import urlparse_cached
from scrapper_base import LinkSpider, DuplicatesPipeline, KeywordMiddleware, LinkItem

logger = logging.getLogger(__name__)


class LloydsSpider(LinkSpider):
    name = 'lloyds'

    allowed_domains = ['muni.cz']
    allowed_kw = ['muni.cz']

    start_urls = ['https://www.muni.cz']

    rules = (
        Rule(LxmlLinkExtractor(allow=(), deny=('dt=[0-9]', 'dt=',
                                               '.+/switcher/.+',
                                               '.+wt\.cg_n=.+',
                                               '.+WT.mc_id=.+',
                                               '.+tagname=.+',
                                               '.+tagid=.+',
                                               'is.muni.cz',
                                               '.+osoba.+',
                                               '.+lide.+',
                                               '.+publikace.+',
                                               '.+predmet.+',
                                               '.+people.+',
                                               '.+publication.+',
                                               '.+Default\.aspx\?p=.+', '.+Default\.aspx\?s=.+',), ),
             callback='parse_obj', follow=False),
    )

    custom_settings = {
        'SPIDER_MIDDLEWARES': {
            'scrapper_base.KeywordMiddleware': 543,
            'scrapy.spidermiddlewares.offsite.OffsiteMiddleware': None
        },
        'ITEM_PIPELINES': {
            # Use if want to prevent duplicates, otherwise useful for frequency analysis
            #'scrapper.DuplicatesPipeline': 10,
        }
    }

    def shoud_follow_link(self, link, response):
        logger.debug("--link %s" % link)
        if 'switcher' in link:
            return False
        return True







