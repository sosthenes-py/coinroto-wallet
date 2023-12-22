import requests
from westwallet_api import WestWalletAPI
import os
import re
import socket


all_coins = {'btc': 'Bitcoin', 'eth': 'Ethereum', 'usdttrc': 'USDT TRC-20', 'ltc': 'Litecoin', 'bch': 'Bitcoin Cash', 'etc': 'Ethereum Classic', 'zec': 'Zcash', 'bnb': 'Binance Coin BEP-20', 'xrp': 'Ripple', 'eos': 'EOS', 'ada': 'Cardano', 'trx': 'TRON', 'doge': 'Dogecoin', 'sol': 'Solana', 'xmr': 'Monero', 'shib': 'Shiba Inu', 'usdctrc': 'USD Coin', 'busd': 'Binance USD', 'dash': 'Dash'}
fees = {
    'btc': {
        'send': 0.0002,
        'receive': 0.0002
    },'eth': {
        'send': 0.0015,
        'receive': 0.0015
    },'usdttrc': {
        'send': 2,
        'receive': 1
    },'ltc': {
        'send': 0.03,
        'receive': 0.01
    },'bch': {
        'send': 0.03,
        'receive': 0.01
    },'etc': {
        'send': 0.07,
        'receive': 0.03
    },'zec': {
        'send': 0.03,
        'receive': 0.01
    },'bnb': {
        'send': 0.007,
        'receive': 0.002
    },'xrp': {
        'send': 1.5,
        'receive': 0.5
    },'eos': {
        'send': 0.4,
        'receive': 0.1
    },'ada': {
        'send': 1.7,
        'receive': 1
    },'trx': {
        'send': 8,
        'receive': 2
    },'doge': {
        'send': 13,
        'receive': 4
    },'sol': {
        'send': 0.07,
        'receive': 0.02
    },'xmr': {
        'send': 7,
        'receive': 2
    },'shib': {
        'send': 400000,
        'receive': 50000
    },'usdctrc': {
        'send': 1.7,
        'receive': 0.2
    },'busd': {
        'send': 1.7,
        'receive': 0.2
    },'dash': {
        'send': 0.01,
        'receive': 0.01
    },
}
WESTWALLET_PUBLIC_KEY = os.environ['WESTWALLET_PUBLIC_KEY']
WESTWALLET_PRIVATE_KEY = os.environ['WESTWALLET_PRIVATE_KEY']


def get_ticker_from_binance(symbol: str, conversion=False, **kwargs):
    """

    :param symbol: Crypto symbol
    :param conversion: Set to True if you want to make conversion
    :param kwargs: If conversion is set to True, include: 'direction' (fd is to USD, bk is otherwise), 'amount' (amount to be converted)
    :return: Returns price of symbol in USD or result of conversion if set
    """
    if symbol != "usdttrc":
        response = requests.get(f"https://api.binance.com/api/v3/ticker/24hr?symbol={symbol.upper()}USDT").json()
        price = float(response['askPrice'])
    else:
        price = 1
    if conversion:
        if kwargs['direction'] == "fd":
            return round(price * float(kwargs['amount']), 2)
        return float(kwargs['amount']) / price
    return price


def generate_wallet(coin, label=""):
    client = WestWalletAPI(WESTWALLET_PUBLIC_KEY, WESTWALLET_PRIVATE_KEY)
    try:
        address = client.generate_address(currency=coin.upper(), ipn_url="", label=label)
    except:
        address = "thisisthenewwalletaddressyouhavecreated"
        return address
    else:
        return address.address


def make_withdrawal(token, qty, addr):
    client = WestWalletAPI(WESTWALLET_PUBLIC_KEY, WESTWALLET_PRIVATE_KEY)
    response = client.create_withdrawal(currency=token, amount=qty, address=addr)


def is_address_valid(token, addr):
    response = requests.get(url="https://api.westwallet.io/wallet/currencies_data")
    for info in response.json():
        if token.upper() in info['tickers']:
            if re.match(info['address_regex'], addr):
                return True
            return False
    return False


def get_token_info(token=None, info=None):
    """

    :param token: currency to retrieve
    :param info: the parameter to get: min_receive, min_withdraw
    :return: returns value
    """
    response = requests.get(url="https://api.westwallet.io/wallet/currencies_data")
    if token and info:
        for res in response.json():
            if token.upper() in res['tickers']:
                return res[info]
        return None
    return response


def get_all_tickers():
    coins_list = [f'"{coin.upper()}USDT"' for coin in list(all_coins) if coin != 'usdttrc']
    coins_list = f'%5B{",".join(coins_list)}%5D'
    response = requests.get(f"https://binance.me/api/v3/ticker/price?symbols={coins_list}").json()
    our_dict = {}
    for res in response:
        our_dict[res['symbol'][:-4].lower()] = res['price']
    our_dict['usdttrc'] = 1
    return our_dict

