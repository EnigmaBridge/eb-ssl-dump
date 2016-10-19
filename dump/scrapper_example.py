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


class ExampleSpider(LinkSpider):
    name = 'example'

    allowed_domains = ['example.com']
    allowed_kw = ['example']

    start_urls = ['https://www.example.com']

    rules = (
        Rule(LxmlLinkExtractor(allow=(), deny=('not-this'), ), callback='parse_obj', follow=False),
    )








