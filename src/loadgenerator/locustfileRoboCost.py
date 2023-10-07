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
from locust import HttpUser, TaskSet, between, events
import re
import json
import math

logger = logging.getLogger(__name__)
FORMAT = "[%(asctime)s %(filename)s->%(funcName)s():%(lineno)s]%(levelname)s: %(message)s"
logging.basicConfig(format=FORMAT)
productInfo = {}
products = []
price = []

@events.init.add_listener
def on_test_start(environment, **kwargs):
    global productInfo
    global products
    global price
    logger.info("Reading products file and initializing data")
    with open("./robotshop_products.json") as f:
        productInfo = json.load(f)
        products = [d["id"] for d in productInfo["products"]]
        price = [float(d["priceUsd"]["units"])+(float(d["priceUsd"]["nanos"])/1000000000.0) for d in productInfo["products"]]
    logger.debug("%s, %s" % (str(products), str(price)))

userNumLock = threading.Lock()
userNum = 251

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

def getProduct(l):
    logger.debug(f"Entered getProduct {l.myUserNum}")
    productNum = random.randint(0, (len(products)-1))
    logger.debug(f"productNum {productNum}")
    product = products[productNum]
    response = l.client.get("/product/" + product,
                 headers={'Tenantname':'Tenant'+l.myUserNum})
    logger.debug("Usr%s: Got product with ID %s." % (l.myUserNum, product))
    logger.debug("Usr%s: Output:\n%s" % (l.myUserNum, response.text))
    productPrice = 0.0
    for line in response.text.splitlines():
        productPriceMatch = re.match("\<p class=\"product-price\"\>\$(?P<productPrice>[0-9]+(\.[0-9]+)?)\<", line.strip())
        if productPriceMatch:
            logger.debug("Product price line: %s" % line)
            if productPriceMatch.group('productPrice'):
                productPrice = float(productPriceMatch.group('productPrice'))
                logger.debug("Product price is (%s)'%f'" % (productPriceMatch.group('productPrice'), productPrice))
            break

    actualPrice = price[productNum] + float(l.myUserNum)
    if math.isclose(productPrice, actualPrice, rel_tol=0.01):
        logger.info("Usr%s: Price of product %s matched: (%f:%f)" % (l.myUserNum,
                                                                     product,
                                                                     productPrice,
                                                                     actualPrice))
    else:
        logger.error("Usr%s: Price of product %s did not match: (%f:%f)" % (l.myUserNum,
                                                                            product,
                                                                            productPrice,
                                                                            actualPrice))
    logger.debug(f"Exiting addToCart {l.myUserNum}")

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
    myUserNum = "251"

    def on_start(self):
        logger.debug(f"Entered on_start {self.myUserNum}")
        global userNum
        userNumLock.acquire()
        self.myUserNum = "%03d" % userNum
        userNum = userNum + 1
        userNumLock.release()

        userName = "roboCost" + self.myUserNum + "@appez.com"
        userFullName = "Robo Cost " + self.myUserNum
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
    getProduct: 1
    }

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(10, 12)

