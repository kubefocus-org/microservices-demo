#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import threading
import time
import logging
from locust import HttpUser, TaskSet, between
import inspect
__FRAME__ = inspect.currentframe()
import re

logger = logging.getLogger(__name__)
FORMAT = "[%(asctime)s %(filename)s->%(funcName)s():%(lineno)s]%(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT)

products = [
    '0PUK6V6EV0',
    '1YMWWN1N4O',
    '2ZYFJ3GM2N',
    '66VCHSJNUP',
    '6E92ZMYYFZ',
    '9SIQT8TOJO',
    'L9ECAV7KIM',
    'LS4PSXUNUM',
    'OLJCESPC7Z']

userNumLock = threading.Lock()
userNum = 1

def index(l):
    logger.debug(f"Entered index {l.myUserNum}")
    l.client.get("/",
                 headers={'Tenantname':'Tenant'+str(l.myUserNum)})
    logger.debug(f"Exiting index {l.myUserNum}")

def setCurrency(l):
    logger.debug(f"Entered setCurrency {l.myUserNum}")
    currencies = ['EUR', 'USD', 'JPY', 'CAD']
    l.client.post("/setCurrency",
                  json={'currency_code': random.choice(currencies)},
                  headers={'Tenantname':'Tenant'+str(l.myUserNum)})
    logger.debug(f"Exiting setCurrency {l.myUserNum}")

def browseProduct(l):
    logger.debug(f"Entered browseProduct {l.myUserNum}")
    l.client.get("/product/" + random.choice(products),
                 headers={'Tenantname':'Tenant'+str(l.myUserNum)})
    logger.debug(f"Exiting browseProduct {l.myUserNum}")

def viewCart(l):
    logger.debug(f"Entered viewCart {l.myUserNum}")
    response = l.client.get("/cart",
                  headers={'Tenantname':'Tenant'+str(l.myUserNum)})
    # logger.debug(response.text)
    prevLineShipping = False
    numItems = 0
    shipCost = "$0.00"
    isCartEmpty = True
    for line in response.text.splitlines():

        numItemMatch = re.match("\<h3\>Cart \((?P<numItems>\d+)\)", line.strip())
        if numItemMatch:
            logger.debug("Number of items line: %s" % line)
            if numItemMatch.group('numItems'):
                numItems = int(numItemMatch.group('numItems'))
                logger.debug("Number of items is '%d'" % numItems)
            isCartEmpty = False

        if prevLineShipping:
            logger.debug("Shipping cost line 1: %s" % line)
            shipCostMatch = re.match("\<div class=\"col pr-md-0 text-right\"\>(?P<cost>.*)\<\/div\>", line.strip())
            if shipCostMatch:
                logger.debug("Shipping cost line 2: %s" % line)
                if shipCostMatch.group('cost'):
                    shipCost = shipCostMatch.group('cost')
                    logger.debug("Shipping cost is: '%s'" % shipCost)
            prevLineShipping = False

        if re.search("\>Shipping\<\/div\>", line):
            prevLineShipping = True

    if (numItems >= int(l.myUserNum)):
        if shipCost != "$0.00":
            logger.error("Usr%s: Free shipping not provided. %03d, %s" % (l.myUserNum, numItems, shipCost))
        else:
            logger.info("Usr%s: Free shipping achieved: %03d, %s. Emptying cart." % (l.myUserNum, numItems, shipCost))
            l.client.post("/cart/empty", headers={'Tenantname':'Tenant'+l.myUserNum})
    elif isCartEmpty:
        logger.info("Usr%s: Cart is empty" % l.myUserNum)
    else:
        logger.info("Usr%s: Free shipping not yet achieved: %03d, %s" % (l.myUserNum, numItems, shipCost))

    logger.debug(f"Exiting viewCart {l.myUserNum}")

def addToCart(l):
    logger.debug(f"Entered addToCart {l.myUserNum}")
    product = random.choice(products)
    l.client.get("/product/" + product,
                 headers={'Tenantname':'Tenant'+str(l.myUserNum)})
    qty = random.choice([1,2,3,4,5,10])
    logger.info("Usr%s: Adding %d products with ID %s to cart." % (l.myUserNum, qty, product))
    l.client.post("/cart", {
        'product_id': product,
        'quantity': qty},
        headers={'Tenantname':'Tenant'+str(l.myUserNum)})
    logger.debug(f"Exiting addToCart {l.myUserNum}")

def checkout(l):
    logger.debug(f"Entered checkout {l.myUserNum}")
    addToCart(l)
    l.client.post("/cart/checkout", {
        'email': 'someone@example.com',
        'street_address': '1600 Amphitheatre Parkway',
        'zip_code': '94043',
        'city': 'Mountain View',
        'state': 'CA',
        'country': 'United States',
        'credit_card_number': '4432-8015-6152-0454',
        'credit_card_expiration_month': '1',
        'credit_card_expiration_year': '2039',
        'credit_card_cvv': '672',
    },
    headers={'Tenantname':'Tenant'+str(l.myUserNum)})
    logger.debug(f"Exiting checkout {l.myUserNum}")

class UserBehavior(TaskSet):
    myUserNum = "000"

    def on_start(self):
        logger.debug(f"Entered on_start {self.myUserNum}")
        global userNum
        userNumLock.acquire()
        self.myUserNum = "%03d" % userNum
        userNum = userNum + 1
        userNumLock.release()

        userName = "shipUsr" + self.myUserNum + "@appez.com"
        userFullName = "Ship User " + self.myUserNum
        userPwd = userName
        self.client.post("/local/register",
                         # headers={"Content-Type":"application/x-www-form-urlencoded"},
                         data={"signupname":userFullName,
                               "signupemail":userName,
                               "signuppwd":userPwd})
        time.sleep(2)
        self.client.post("/local/login",
                         # headers={"Content-Type":"application/x-www-form-urlencoded"},
                         data={"signinemail":userName,
                               "signinpwd":userPwd})
        time.sleep(2)
        index(self)
        logger.debug(f"Exiting on_start {self.myUserNum}")

    '''
    tasks = {index: 1,
        setCurrency: 2,
        browseProduct: 10,
        addToCart: 2,
        viewCart: 3,
        checkout: 1}
    '''
    tasks = {
    addToCart: 1,
    viewCart: 1
    }

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(10, 12)

