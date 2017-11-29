#TODO
#Previous - could reduce server involvement by storing previous hash, requesting server on boot + updating with each transaction
#Convert PoW to cpython or even a c binary that could be dropped in to increase speed (would also benefit from multicore support)
#Increase timeout on server

import urwid
import websocket
import json
import sys, os, logging
from websocket import create_connection

import binascii
import random, getpass
from pyblake2 import blake2b
from bitstring import BitArray
from pure25519 import ed25519_oop as ed25519
from simplecrypt import encrypt, decrypt
from configparser import SafeConfigParser
import pyqrcode

default_representative = \
        'xrb_16k5pimotz9zehjk795wa4qcx54mtusk8hc5mdsjgy57gnhbj3hj6zaib4ic'
raw_in_xrb = 1000000000000000000000000000000.0
choices = u'Send,Account History,Display QR Code,,Configure PoW,Configure Rep,Configure Server,,Refresh,Quit'.split(',')

logging.basicConfig(filename="sample.log", level=logging.INFO)

def xrb_account(address):
    # Given a string containing an XRB address, confirm validity and
    # provide resulting hex address
    if len(address) == 64 and (address[:4] == 'xrb_'):
        # each index = binary value, account_lookup[0] == '1'
        account_map = "13456789abcdefghijkmnopqrstuwxyz"
        account_lookup = {}
        # populate lookup index with prebuilt bitarrays ready to append
        for i in range(32):
            account_lookup[account_map[i]] = BitArray(uint=i,length=5)

        # we want everything after 'xrb_' but before the 8-char checksum
        acrop_key = address[4:-8]
        # extract checksum
        acrop_check = address[-8:]

        # convert base-32 (5-bit) values to byte string by appending each
        # 5-bit value to the bitstring, essentially bitshifting << 5 and
        # then adding the 5-bit value.
        number_l = BitArray()
        for x in range(0, len(acrop_key)):
            number_l.append(account_lookup[acrop_key[x]])
        # reduce from 260 to 256 bit (upper 4 bits are never used as account
        # is a uint256)
        number_l = number_l[4:]

        check_l = BitArray()
        for x in range(0, len(acrop_check)):
            check_l.append(account_lookup[acrop_check[x]])

        # reverse byte order to match hashing format
        check_l.byteswap()
        result = number_l.hex.upper()

        # verify checksum
        h = blake2b(digest_size=5)
        h.update(number_l.bytes)
        if (h.hexdigest() == check_l.hex):
            return result
        else:
            return False
    else:
        return False

def account_xrb(account):
    # Given a string containing a hex address, encode to public address
    # format with checksum
    # each index = binary value, account_lookup['00001'] == '3'
    account_map = "13456789abcdefghijkmnopqrstuwxyz"
    account_lookup = {}
    # populate lookup index for binary string to base-32 string character
    for i in range(32):
        account_lookup[BitArray(uint=i,length=5).bin] = account_map[i]
    # hex string > binary
    account = BitArray(hex=account)

    # get checksum
    h = blake2b(digest_size=5)
    h.update(account.bytes)
    checksum = BitArray(hex=h.hexdigest())

    # encode checksum
    # swap bytes for compatibility with original implementation
    checksum.byteswap()
    encode_check = ''
    for x in range(0,int(len(checksum.bin)/5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_check += account_lookup[checksum.bin[x*5:x*5+5]]

    # encode account
    encode_account = ''
    while len(account.bin) < 260:
        # pad our binary value so it is 260 bits long before conversion
        # (first value can only be 00000 '1' or 00001 '3')
        account = '0b0' + account
    for x in range(0,int(len(account.bin)/5)):
        # each 5-bit sequence = a base-32 character from account_map
        encode_account += account_lookup[account.bin[x*5:x*5+5]]

    # build final address string
    return 'xrb_'+encode_account+encode_check

def private_public(private):
    return ed25519.SigningKey(private).get_verifying_key().to_bytes()

def seed_account(seed, index):
    # Given an account seed and index #, provide the account private and
    # public keys
    h = blake2b(digest_size=32)

    seed_data = BitArray(hex=seed)
    seed_index = BitArray(int=index,length=32)

    h.update(seed_data.bytes)
    h.update(seed_index.bytes)

    account_key = BitArray(h.digest())
    return account_key.bytes, private_public(account_key.bytes)

def get_pow(hash, type):

    cached_work = parser.get('wallet', 'cached_pow')
    if cached_work == '' or type == 'open':
        #Generate work for block
        pow_source = parser.get('wallet', 'pow_source')
        if pow_source == 'external':
            data = json.dumps({'action' : 'work_generate', 'hash' : hash})
            ws.send(data)
            block_work = json.loads(str(ws.recv()))
            work = block_work['work']
        else:
            response = urwid.Text([u'Running Internal PoW\nThis might take some time...'])
            done = urwid.Button(u'Back')
            urwid.connect_signal(done, 'click', return_to_main)
            main.original_widget = urwid.Filler(urwid.Pile([response,
                urwid.AttrMap(done, None, focus_map='reversed')]))
            pow_work = pow_generate(hash)
            work = str(pow_work, 'ascii')

        return work
            
    else:
        save_config('cached_pow', '')
        return cached_work

def pow_threshold(check):
    if check > b'\xFF\xFF\xFF\xC0\x00\x00\x00\x00': return True
    else: return False

def pow_generate(hash):
    hash_bytes = bytearray.fromhex(hash)
    #print(hash_bytes.hex())
    #time.sleep(5)
    test = False
    inc = 0
    while test == False:
        inc += 1
        # generate random array of bytes
        random_bytes = bytearray((random.getrandbits(8) for i in range(8)))
        for r in range(0,256):
            # iterate over the last byte of the random bytes
            random_bytes[7] =(random_bytes[7] + r) % 256
            h = blake2b(digest_size=8)
            h.update(random_bytes)
            h.update(hash_bytes)
            final = bytearray(h.digest())
            final.reverse()
            test = pow_threshold(final)
            if test:
                break

    random_bytes.reverse()
    return binascii.hexlify(random_bytes)

def get_balance(account):
    data = json.dumps({'action' : 'account_balance', 'account' : account})
    ws.send(data)

    balance_result =  json.loads(str(ws.recv()))
    #print(balance_result['balance'])

    balance = float(balance_result['balance']) / raw_in_xrb
    return balance

def get_raw_balance(account):
    data = json.dumps({'action' : 'account_balance', 'account' : account})
    ws.send(data)

    balance_result =  json.loads(str(ws.recv()))
    #print(balance_result['balance'])

    balance = int(balance_result['balance'])
    return balance

def get_previous():
    #Get account info
    accounts_list = [account]
    data = json.dumps({'action' : 'accounts_frontiers', 'accounts' : accounts_list})
    ws.send(data)
    result =  ws.recv()
    #print(result)
    account_info = json.loads(str(result))
    previous = account_info['frontiers'][account]

    return previous

def get_pending():
    #Get pending blocks
    data = json.dumps({'action' : 'pending', 'account' : account})
    
    ws.send(data)
    
    pending_blocks =  ws.recv()
    #print("Received '%s'" % pending_blocks)
    
    rx_data = json.loads(str(pending_blocks))

    return rx_data['blocks']

def save_config(variable, value):
    cfgfile = open("config.ini",'w')
    parser.set('wallet', variable, value)
    parser.write(cfgfile)
    cfgfile.close()


def send_xrb(dest_address, final_balance):
    previous = get_previous()

    priv_key, pub_key = seed_account(seed,index)

    hex_balance = hex(final_balance)
    hex_final_balance = hex_balance[2:].upper().rjust(32, '0')
    #print(final_balance)

    #print("Starting PoW Generation")
    work = get_pow(previous, 'send')
    #workbytes = pow_generate(previous)
    #work = str(workbytes, 'ascii')
    #print("Completed PoW Generation")

    #Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex=previous).bytes)
    bh.update(BitArray(hex=xrb_account(dest_address)).bytes)
    bh.update(BitArray(hex=hex_final_balance).bytes)

    sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')

    finished_block = '{ "type" : "send", "destination" : "%s", "balance" : "%s", "previous" : "%s" , "work" : "%s", "signature" : "%s" }' % (dest_address, hex_final_balance, previous, work, signature)

    data = json.dumps({'action' : 'process', 'block' : finished_block})
    #print(data)
    ws.send(data)

    block_reply = ws.recv()
    logging.info(block_reply)
    #print(block_reply)
    return block_reply

def receive_xrb(_loop, _data):
    pending = get_pending()

    if len(pending) > 0:

        data = json.dumps({'action' : 'account_info', 'account' : account})
        ws.send(data)
        info =  ws.recv()
        if len(info) == 37:
            #print('Not found')
            open_xrb()
        else:
            source = pending[0]

            #Get account info
            previous = get_previous()

            priv_key, pub_key = seed_account(seed,index)

            #print("Starting PoW Generation")
            work = get_pow(previous, 'receive')
            #print("Completed PoW Generation")

            #Calculate signature
            bh = blake2b(digest_size=32)
            bh.update(BitArray(hex=previous).bytes)
            bh.update(BitArray(hex=source).bytes)

            sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
            signature = str(binascii.hexlify(sig), 'ascii')
            finished_block = '{ "type" : "receive", "source" : "%s", "previous" : "%s" , "work" : "%s", "signature" : "%s" }' % (source, previous, work, signature)

            data = json.dumps({'action' : 'process', 'block' : finished_block})
            #print(data)
            ws.send(data)

            block_reply = ws.recv()
            logging.info(block_reply)
            save_config('balance', str(get_balance(account)))
            #print(block_reply)
    else:
    #Lets cache a PoW for later
        if parser.get('wallet', 'cached_pow') == '' and parser.get('wallet', 'open') == '1':
            previous = get_previous()
            work = get_pow(previous, 'cache')
            save_config('cached_pow', work)
            logging.info("Cached PoW Block")


    main_loop.set_alarm_in(60, receive_xrb)

def open_xrb():
    representative = parser.get('wallet', 'representative')
    #Get pending blocks
    data = json.dumps({'action' : 'pending', 'account' : account})

    ws.send(data)

    pending_blocks =  ws.recv()
    #print("Received '%s'" % pending_blocks)

    rx_data = json.loads(str(pending_blocks))
    #for blocks in rx_data['blocks']:
    #print(rx_data['blocks'][0])
    source = rx_data['blocks'][0]

    priv_key, pub_key = seed_account(seed,index)
    public_key = ed25519.SigningKey(priv_key).get_verifying_key().to_ascii(encoding="hex")

    #print("Starting PoW Generation")
    work = get_pow(str(public_key, 'ascii'), 'open')
    #print("Completed PoW Generation")

    #Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex=source).bytes)
    bh.update(BitArray(hex=xrb_account(representative)).bytes)
    bh.update(BitArray(hex=xrb_account(account)).bytes)

    sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')
    finished_block = '{ "type" : "open", "source" : "%s", "representative" : "%s" , "account" : "%s", "work" : "%s", "signature" : "%s" }' % (source, representative, account, work, signature)

    data = json.dumps({'action' : 'process', 'block' : finished_block})
    #print(data)
    ws.send(data)

    block_reply = ws.recv()
    logging.info(block_reply)

    save_config('open', '1')
    #print(block_reply)

def change_xrb():
    representative = parser.get('wallet', 'representative')
    previous = get_previous()

    priv_key, pub_key = seed_account(seed,index)
    public_key = ed25519.SigningKey(priv_key).get_verifying_key().to_ascii(encoding="hex")

    #print("Starting PoW Generation")
    work = get_pow(previous, 'change')
    #print("Completed PoW Generation")

    #Calculate signature
    bh = blake2b(digest_size=32)
    bh.update(BitArray(hex=previous).bytes)
    bh.update(BitArray(hex=xrb_account(representative)).bytes)

    sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())
    signature = str(binascii.hexlify(sig), 'ascii')
    finished_block = '{ "type" : "change", "previous" : "%s", "representative" : "%s" , "work" : "%s", "signature" : "%s" }' % (previous, representative, work, signature)

    data = json.dumps({'action' : 'process', 'block' : finished_block})
    #print(data)
    ws.send(data)

    block_reply = ws.recv()
    logging.info(block_reply)
#print(block_reply)

def menu(title, choices):
    body = [urwid.Text(title), urwid.Divider()]
    address_txt = urwid.Text(account)
    body.append(urwid.AttrMap(address_txt, None, focus_map='reversed'))


    xrb_balance = 'Balance: ' + parser.get('wallet', 'balance')  + ' Mxrb'
    balance_txt = urwid.Text(xrb_balance)
    body.append(urwid.AttrMap(balance_txt, None, focus_map='reversed'))

    paragraph_txt = urwid.Text('\n')
    body.append(urwid.AttrMap(paragraph_txt, None, focus_map='reversed'))

    for c in choices:
        button = urwid.Button(c)
        urwid.connect_signal(button, 'click', item_chosen, c)
        body.append(urwid.AttrMap(button, None, focus_map='reversed'))
    return urwid.ListBox(urwid.SimpleFocusListWalker(body))

def item_chosen(button, choice):

    if choice == 'Refresh':
        save_config('balance', str(get_balance(account)))
        main.original_widget = urwid.Padding(menu(u'RetroXRBWallet', choices),
                                             left=2, right=2)

    elif choice == 'Send':
       response = urwid.Text([u'Balance: ', parser.get('wallet', 'balance'), u'Mxrb\n'])
       xrb_edit = urwid.Edit(u"Destination Address?\n")
       amount_edit = urwid.Edit(u"Amount in Mxrb?\n")
       send = urwid.Button(u'Send')
       done = urwid.Button(u'Back')
       urwid.connect_signal(send, 'click', confirm_send,
               user_args=[xrb_edit, amount_edit])
       urwid.connect_signal(done, 'click', return_to_main)
       main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(xrb_edit, None, focus_map='reversed'),
            urwid.AttrMap(amount_edit, None, focus_map='reversed'),
            urwid.AttrMap(send, None, focus_map='reversed'),
            urwid.AttrMap(done, None, focus_map='reversed')]))

    elif choice == 'Configure PoW':
        pow_source = parser.get('wallet', 'pow_source')
        response = urwid.Text([u'Configure PoW Source\n'])
        if pow_source == 'external':
            #response = urwid.Text([u'external\n'])
            external_pow = urwid.CheckBox(u'External PoW', state=True)
            internal_pow = urwid.CheckBox(u'Internal PoW', state=False)
        else:
            #response = urwid.Text([u'internal\n'])
            external_pow = urwid.CheckBox(u'External PoW', state=False)
            internal_pow = urwid.CheckBox(u'Internal PoW', state=True)
        save = urwid.Button(u'Save')
        done = urwid.Button(u'Back')
        urwid.connect_signal(done, 'click', return_to_main)
        urwid.connect_signal(save, 'click', change_pow, user_args=[internal_pow, external_pow])
        main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(internal_pow, None, focus_map='reversed'),
            urwid.AttrMap(external_pow, None, focus_map='reversed'),
            urwid.AttrMap(save, None, focus_map='reversed'),
            urwid.AttrMap(done, None, focus_map='reversed')]))

    elif choice == 'Configure Rep':
        representative = parser.get('wallet', 'representative')
        response = urwid.Text([u'Configure Representative\n'])
        xrb_rep = urwid.Edit(u"Representative:\n", edit_text=representative)
        save = urwid.Button(u'Save')
        done = urwid.Button(u'Back')
        urwid.connect_signal(done, 'click', return_to_main)
        urwid.connect_signal(save, 'click', update_rep, user_args=[xrb_rep])
        main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(xrb_rep, None, focus_map='reversed'),
            urwid.AttrMap(save, None, focus_map='reversed'),
            urwid.AttrMap(done, None, focus_map='reversed')]))

    elif choice == 'Configure Server':
        node_server = parser.get('wallet', 'server')
        response = urwid.Text([u'Configure Server\n'])
        xrb_server = urwid.Edit(u"Server:\n", edit_text=node_server)
        save = urwid.Button(u'Save and Restart')
        done = urwid.Button(u'Back')
        urwid.connect_signal(done, 'click', return_to_main)
        urwid.connect_signal(save, 'click', update_server, user_args=[xrb_server])
        main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(xrb_server, None, focus_map='reversed'),
            urwid.AttrMap(save, None, focus_map='reversed'),
            urwid.AttrMap(done, None, focus_map='reversed')]))

    elif choice == 'Display QR Code':
        data = 'xrb:' + account
        xrb_qr = pyqrcode.create(data, error='L', version=4, mode=None, encoding='iso-8859-1')
        list = []
        for blocks in xrb_qr.text():
            if blocks == '1':
                list.append(u"\u2588")
                list.append(u"\u2588")
            elif blocks == '0':
                list.append(chr(32))
                list.append(chr(32))
            else:
                list.append('\n')
        response = urwid.Text(list)
        done = urwid.Button(u'Back')
        urwid.connect_signal(done, 'click', return_to_main)
        main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(done, None)]))

    elif choice == 'Account History':
        data = json.dumps({ "action": "account_block_count", "account": account })
        ws.send(data)
        block_count =  ws.recv()
        rx_data = json.loads(str(block_count))
        if 'error' in rx_data:
            account_block_count = '0'
            history_title = 'Account History (' + account_block_count + ')'
            body = [urwid.Text(history_title), urwid.Divider()]
        else:
            account_block_count = rx_data['block_count']
            data = json.dumps({'action' : 'account_history', 'account' : account, 'count': int(account_block_count)})
            ws.send(data)
            history_blocks =  ws.recv()
            rx_data = json.loads(str(history_blocks))
            
            history_title = 'Account History (' + account_block_count + ')'
            body = [urwid.Text(history_title), urwid.Divider()]
            rx_data['history'].reverse()
            
            first_done = urwid.Button(u'Back')
            urwid.connect_signal(first_done, 'click', return_to_main)
            body.append(urwid.AttrMap(first_done, None, focus_map='reversed'))
            
            count = 0
            for blocks in rx_data['history']:
                count = count + 1
                #print(blocks['amount'])
                #str(float(blocks['amount']) / raw_in_xrb)
                ind_history = str(count) + ') ' + blocks['type'] + ' ' + str(float(blocks['amount']) / raw_in_xrb) + 'Mxrb ' + blocks['account'] + '\n'
                address_txt = urwid.Text(ind_history)
                body.append(urwid.AttrMap(address_txt, None, focus_map='reversed'))

        done = urwid.Button(u'Back')
        urwid.connect_signal(done, 'click', return_to_main)
        body.append(urwid.AttrMap(done, None, focus_map='reversed'))
        main.original_widget = urwid.ListBox(urwid.SimpleListWalker(body))


    elif choice == 'Quit':
       response = urwid.Text([u'Are You Sure?\n'])
       yes = urwid.Button(u'Yes')
       no = urwid.Button(u'No')
       urwid.connect_signal(yes, 'click', exit_program)
       urwid.connect_signal(no, 'click', return_to_main)
       main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(yes, None, focus_map='reversed'),
            urwid.AttrMap(no, None, focus_map='reversed')]))

def update_rep(xrb_rep, button):
    new_rep = xrb_rep.edit_text
    if len(new_rep) != 64 or new_rep[:4] != "xrb_":
        print('Error')
    else:
        save_config('representative', new_rep)
        #Send change block
        change_xrb()
        main.original_widget = urwid.Padding(menu(u'RetroXRBWallet', choices),
                                             left=2, right=2)

def update_server(xrb_server, button):
    new_server = xrb_server.edit_text
    save_config('server', new_server)
    ws.close()
    raise urwid.ExitMainLoop()


def change_pow(internal_pow, external_pow, button):
    #print(external_pow.get_state())
    if external_pow.get_state() == True:
        save_config('pow_source', 'external')
        pow_source = 'external'
        #print('external')
    else:
        print('internal')
        save_config('pow_source', 'internal')
        pow_source = 'internal'

    #print(pow_source)
    main.original_widget = urwid.Padding(menu(u'RetroXRBWallet', choices),
                left=2, right=2)


def confirm_send(final_address, xrb_amount, button):
    #Lets check the details here
    #Calculate amount to send
    #send_amount is in Mxrb,
    send_amount = xrb_amount.edit_text
    send_address = final_address.edit_text
    try:
        rai_send = float(send_amount) * 1000000 #float of total send
        raw_send = str(int(rai_send)) + '000000000000000000000000'
        #Create the new balance
        int_balance = int(get_raw_balance(account))
        new_balance = int_balance - int(raw_send)
        #print(new_balance)

        if len(send_address) != 64 or send_address[:4] != "xrb_":
            response = urwid.Text([u'Error, incorrect address\n'])
            back = urwid.Button(u'Back')
            urwid.connect_signal(back, 'click', return_to_main)
            main.original_widget = urwid.Filler(urwid.Pile([response,
                urwid.AttrMap(back, None, focus_map='reversed')]))

        else:
            response = urwid.Text([u'Sending...\n',
                    u'Dest ', str(final_address.edit_text),
                    u'\nAmount      ', str(raw_send),
                    u'\nNew Balance ', str(new_balance),
                    u'\nAre You Sure?'])
            yes = urwid.Button(u'Yes')
            no = urwid.Button(u'No')
            urwid.connect_signal(yes, 'click', process_send,
                    user_args=[final_address, new_balance])
            urwid.connect_signal(no, 'click', return_to_main)
            main.original_widget = urwid.Filler(urwid.Pile([response,
                    urwid.AttrMap(yes, None, focus_map='reversed'),
                    urwid.AttrMap(no, None, focus_map='reversed')]))
    except:
        response = urwid.Text([u'Error, incorrect amount\n'])
        back = urwid.Button(u'Back')
        urwid.connect_signal(back, 'click', return_to_main)
        main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(back, None, focus_map='reversed')]))


def process_send(final_address, final_balance, button):
    outcome = send_xrb(str(final_address.edit_text), final_balance)
    if len(outcome) == 4:
        response = urwid.Text([u'Success'])
        save_config('balance', str(get_balance(account)))
    else:
       response = urwid.Text([u'Failed'])

    done = urwid.Button(u'Ok')
    urwid.connect_signal(done, 'click', return_to_main)
    main.original_widget = urwid.Filler(urwid.Pile([response,
            urwid.AttrMap(done, None, focus_map='reversed')]))

def return_to_main(button):
    main.original_widget = urwid.Padding(menu(u'RetroXRBWallet', choices),
            left=2, right=2)

def exit_program(button):
    ws.close()
    raise urwid.ExitMainLoop()

def read_encrypted(password, filename, string=True):
    with open(filename, 'rb') as input:
        ciphertext = input.read()
        plaintext = decrypt(password, ciphertext)
        if string:
            return plaintext.decode('utf8')
        else:
            return plaintext

def write_encrypted(password, filename, plaintext):
    with open(filename, 'wb') as output:
        ciphertext = encrypt(password, plaintext)
        output.write(ciphertext)

parser = SafeConfigParser()
config_files = parser.read('config.ini')

while True:
    password = getpass.getpass('Enter password: ')
    password_confirm = getpass.getpass('Confirm password: ')
    if password == password_confirm:
        break
    print("Password Mismatch!")

if len(config_files) == 0:
    print("Generating Wallet Seed")
    full_wallet_seed = hex(random.SystemRandom().getrandbits(256))
    wallet_seed = full_wallet_seed[2:].upper()
    print("Wallet Seed (make a copy of this in a safe place!): ", wallet_seed)
    write_encrypted(password, 'seed.txt', wallet_seed)

    cfgfile = open("config.ini",'w')
    parser.add_section('wallet')
    priv_key, pub_key = seed_account(str(wallet_seed), 0)
    public_key = str(binascii.hexlify(pub_key), 'ascii')
    print("Public Key: ", str(public_key))

    account = account_xrb(str(public_key))
    print("Account Address: ", account)

    parser.set('wallet', 'account', account)
    parser.set('wallet', 'index', '0')
    parser.set('wallet', 'representative', default_representative)
    parser.set('wallet', 'pow_source', 'internal')
    parser.set('wallet', 'server', 'wss://yapraiwallet.space')
    parser.set('wallet', 'cached_pow', '')
    parser.set('wallet', 'balance', '0')
    parser.set('wallet', 'open', '0')

    parser.write(cfgfile)
    cfgfile.close()

    index = 0
    seed = wallet_seed
else:
    print("Config file found")
    print("Decoding wallet seed with your password")
    try:
        seed = read_encrypted(password, 'seed.txt', string=True)
    except:
        print('\nError decoding seed, check password and try again')
        sys.exit()

account = parser.get('wallet', 'account')
index = int(parser.get('wallet', 'index'))
representative = parser.get('wallet', 'representative')
pow_source = parser.get('wallet', 'pow_source')
node_server = parser.get('wallet', 'server')
cached_work = parser.get('wallet', 'cached_pow')
saved_balance =float(parser.get('wallet', 'balance'))
account_open = parser.get('wallet', 'open')

try:
    ws = create_connection(node_server)
except:
    print('\nError - unable to connect to backend server\nTry again later or change the server in config.ini')
    sys.exit()

main = urwid.Padding(menu(u'RetroXRBWallet', choices), left=2, right=2)
top = urwid.Overlay(main, urwid.SolidFill(u'\N{MEDIUM SHADE}'),
        align='center', width=('relative', 90),
        valign='middle', height=('relative', 80),
        min_width=20, min_height=9)

main_loop = urwid.MainLoop(top, palette=[('reversed', 'standout', '')])
main_loop.set_alarm_in(10, receive_xrb)
main_loop.run()
