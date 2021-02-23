import logging
import os
import requests
from bs4 import BeautifulSoup
import time


class XamVN:

    __current_page = 1
    __requests_headers: dict = None
    __cookies: dict = None
    f = requests.Session()
    __log = logging.getLogger(__name__)

    def __init__(self, headers: dict, cookies: dict) -> None:
        self.__requests_headers = headers
        self.__cookies = cookies
        self.__log.info("XamVNUtils is initialized!!")
        pass

    def apply_params(self, **kwargs) -> None:
        if 'URL' in kwargs:
            self.__URL = kwargs['URL']
        if 'from_page' in kwargs:
            self.__from_page = kwargs['from_page']
        if 'to_page' in kwargs:
            self.__to_page = kwargs['to_page']
        if 'config' in kwargs:
            self.__config = kwargs['config']

    def get_element_url_and_download(self, elements) -> None:
        count = 0
        all_link = set()
        for element in elements:
            # link = element.get_attribute('src')
            link = None
            if 'src' in element:
                link = element['src']
            elif 'href' in element:
                link = element['href']

            if link is not None and not str(link).startswith("http"):
                link = "https://xamvn.us" + link
            # Getting images that are uploaded by user, or embed by users, not avatar, logo, blah
            if 'attachments' in link or 'proxy.php' in link or 'video' in link:
                all_link.add(link)

        for link in all_link:
            self.__log.info("Getting URL: %s" % link)

            self.__log.info("Sleeping for %s second" %
                            str(self.__config['CHROME-DRIVER']['interval-between-crawl']))
            time.sleep(int(self.__config['CHROME-DRIVER']
                           ['interval-between-crawl']))
            count += 1
            req = self.f.get(
                link, headers=self.__requests_headers, cookies=self.__cookies)
            self.__log.info("Status code: " + str(req.status_code))
            if req.status_code == 200:
                self.__log.info("Downloading from URL: %s", link)
                if not os.path.exists(
                        os.path.join(self.__config['XAMVN']['default-download-dir'], str(self.__current_page))):
                    os.makedirs(
                        os.path.join(self.__config['XAMVN']['default-download-dir'], str(self.__current_page)))
                file_type = str(req.headers['Content-Type']).split('/')[-1]
                with open(os.path.join(self.__config['XAMVN']['default-download-dir'], str(self.__current_page),
                                       str(count) + "." + file_type), 'wb') as file:
                    file.write(req.content)
                self.__log.info("Done getting URL: %s" % link)

    def crawl(self,):
        # Get URL, to get some cookies, blah blah, and parse them to the fucking request
        self.__current_page = 1
        if self.__from_page is not None:
            self.__current_page = int(self.__from_page)
        self.__log.info("Setting cookies")
        self.__log.info(self.__cookies)
        for cook in self.__cookies:
            self.__log.debug('Adding cookie: %s -- value: %s' %
                             (cook, self.__cookies[cook]))
            self.f.cookies.set(cook, self.__cookies[cook])
            # break
        while self.__current_page < self.__to_page + 1:
            self.__log.info('Getting page: %s' % str(self.__current_page))
            req = self.f.get(self.__URL + '/page-' +
                             str(self.__current_page), headers=self.__requests_headers, cookies=self.f.cookies)

            soup = BeautifulSoup(req.text, "html.parser")
            images = soup.find_all('img')
            images_from_a_tag = soup.find_all('a')
            if len(images_from_a_tag) != 0:
                for img in images_from_a_tag:
                    images.append(img)

            # iamges_from_zoomer = soup.find_all()
            # Set headers to request headers
            # Get all the images
            if len(images) != 0:
                self.get_element_url_and_download(images)
            else:
                self.__log.info('Cannot find any images')
            # Get all the videos
            videos = soup.find_all('source')
            if len(videos) != 0:
                self.get_element_url_and_download(videos)
            self.__current_page += 1
