(function($){

    var gen_from = 'pass';
    var gen_compressed = false;
    var gen_eckey = null;
    var gen_pt = null;
    var gen_ps_reset = false;
    var TIMEOUT = 10;
    var timeout = null;
    var genRandomPassLength = 8;

    function parseBase58Check(address) {
        var bytes = Bitcoin.Base58.decode(address);
        var end = bytes.length - 4;
        var hash = bytes.slice(0, end);
        var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});
        if (checksum[0] != bytes[end] ||
            checksum[1] != bytes[end+1] ||
            checksum[2] != bytes[end+2] ||
            checksum[3] != bytes[end+3])
                throw new Error("Wrong checksum");
        var version = hash.shift();
        return [version, hash];
    }

    encode_length = function(len) {
        if (len < 0x80)
            return [len];
        else if (len < 255)
            return [0x80|1, len];
        else
            return [0x80|2, len >> 8, len & 0xff];
    }
    
    encode_id = function(id, s) {
        var len = encode_length(s.length);
        return [id].concat(len).concat(s);
    }

    encode_integer = function(s) {
        if (typeof s == 'number')
            s = [s];
        return encode_id(0x02, s);
    }

    encode_octet_string = function(s)  {
        return encode_id(0x04, s);
    }

    encode_constructed = function(tag, s) {
        return encode_id(0xa0 + tag, s);
    }

    encode_bitstring = function(s) {
        return encode_id(0x03, s);
    }

    encode_sequence = function() {
        sequence = [];
        for (var i = 0; i < arguments.length; i++)
            sequence = sequence.concat(arguments[i]);
        return encode_id(0x30, sequence);
    }

    function getEncoded(pt, compressed) {
       var x = pt.getX().toBigInteger();
       var y = pt.getY().toBigInteger();
       var enc = integerToBytes(x, 32);
       if (compressed) {
         if (y.isEven()) {
           enc.unshift(0x02);
         } else {
           enc.unshift(0x03);
         }
       } else {
         enc.unshift(0x04);
         enc = enc.concat(integerToBytes(y, 32));
       }
       return enc;
    }

    function getDER(eckey, compressed) {
        var curve = getSECCurveByName("secp256k1");
        var _p = curve.getCurve().getQ().toByteArrayUnsigned();
        var _r = curve.getN().toByteArrayUnsigned();
        var encoded_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01];

        var secret = integerToBytes(eckey.priv, 32);
        var encoded_gxgy = getEncoded(curve.getG(), compressed);
        var encoded_pub = getEncoded(gen_pt, compressed);

        return encode_sequence(
            encode_integer(1),
            encode_octet_string(secret),
            encode_constructed(0,
                encode_sequence(
                    encode_integer(1),
                    encode_sequence(
                        encoded_oid, //encode_oid(*(1, 2, 840, 10045, 1, 1)), //TODO
                        encode_integer([0].concat(_p))
                    ),
                    encode_sequence(
                        encode_octet_string([0]),
                        encode_octet_string([7])
                    ),
                    encode_octet_string(encoded_gxgy),
                    encode_integer([0].concat(_r)),
                    encode_integer(1)
                )
            ),
            encode_constructed(1, 
                encode_bitstring([0].concat(encoded_pub))
            )
        );
    }

    function pad(str, len, ch) {
        padding = '';
        for (var i = 0; i < len - str.length; i++) {
            padding += ch;
        }
        return padding + str;
    }

    function setErrorState(field, err, msg) {
        group = field.closest('.control-group');

        if (err) {
            group.addClass('error');
        } else {
            group.removeClass('error');
        }

        var e = group.find('.errormsg');
        if (e) {
            e.text(msg||'');
        }
    }
    
    // Some cross-domain magic (to bypass Access-Control-Allow-Origin)
    function get_json(url, onSuccess, onError, postdata) {
      
        var useYQL = false;

        if (useYQL) {
            var q = 'select * from html where url="'+url+'"';
            if (postdata) {
                q = 'use "http://brainwallet.github.com/js/htmlpost.xml" as htmlpost; ';
                q += 'select * from htmlpost where url="' + url + '" ';
                q += 'and postdata="' + postdata + '" and xpath="//p"';
            }
            url = 'https://query.yahooapis.com/v1/public/yql?q=' + encodeURIComponent(q);
        }
        else {
            url = 'http://jsonp.jit.su/?url='+encodeURIComponent(url)+"&callback=?";
        }

        $.ajax({
            url: url,
            type: "GET",
            dataType: "jsonp",
            success: function(res) {
                onSuccess(useYQL ? $(res).find('results').text() : res);
            },
            error:function (xhr, opt, err) {
                if (onError)
                    onError(err);
            }
        });
    }

    function gen_random() {
        $('#pass').val('');
        $('#hash').focus();
        gen_from = 'hash';
        $('#from_hash').button('toggle');
        update_gen();
        var bytes = Crypto.util.randomBytes(32);
        $('#hash').val(Crypto.util.bytesToHex(bytes));
        generate();
    }

    function update_gen() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        $('#pass').attr('readonly', gen_from != 'pass');
        $('#hash').attr('readonly', gen_from != 'hash');
        $('#sec').attr('readonly', gen_from != 'sec');
        $('#sec').parent().parent().removeClass('error');
    }

    function genUpdateLabel() {
      $('#genMsg').text($('#from_'+gen_from).attr('title'));
    }

    function update_gen_from() {
        gen_from = $(this).attr('id').substring(5);
        genUpdateLabel();
        update_gen();
        if (gen_from == 'pass') {
            if (gen_ps_reset) {
                gen_ps_reset = false;
                onChangePass();
            }
            $('#pass').focus();
        } else if (gen_from == 'hash') {
            $('#hash').focus();
        } else if (gen_from == 'sec') {
            $('#sec').focus();
        }
    }

    function update_gen_from_focus() {
        gen_from = $(this).attr('id');
        update_gen();
        if (gen_from == 'pass') {
            if (gen_ps_reset) {
                gen_ps_reset = false;
                onChangePass();
            }
        }
        $('#from_'+gen_from).button('toggle');
    }

    function generate() {
        var hash_str = pad($('#hash').val(), 64, '0');

        var hash = Crypto.util.hexToBytes(hash_str);

        eckey = new Bitcoin.ECKey(hash);

        gen_eckey = eckey;

        try {
            var curve = getSECCurveByName("secp256k1");
            gen_pt = curve.getG().multiply(eckey.priv);
            gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
            gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
            var addr = eckey.getBitcoinAddress();
            setErrorState($('#hash'), false);
        } catch (err) {
            //console.info(err);
            setErrorState($('#hash'), true, 'Invalid secret exponent (must be non-zero value)');
            return;
        }

        gen_update();
    }

    function update_gen_compressed() {
        setErrorState($('#hash'), false);
        setErrorState($('#sec'), false);
        gen_compressed = $(this).attr('id') == 'compressed';
        gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
        gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
        gen_update();
    }

    function gen_update() {

        var eckey = gen_eckey;
        var compressed = gen_compressed;

        var hash_str = pad($('#hash').val(), 64, '0');
        var hash = Crypto.util.hexToBytes(hash_str);

        var hash160 = eckey.getPubKeyHash();

        var addr = eckey.getBitcoinAddress();
        $('#addr').val(addr);

        var h160 = Crypto.util.bytesToHex(hash160);
        $('#h160').val(h160);

        var payload = hash;

        if (compressed)
            payload.push(0x01);

        var sec = new Bitcoin.Address(payload); sec.version = 128;
        $('#sec').val(sec);

        var pub = Crypto.util.bytesToHex(getEncoded(gen_pt, compressed));
        $('#pub').val(pub);

        var der = Crypto.util.bytesToHex(getDER(eckey, compressed));
        $('#der').val(der);

        var qr = qrcode(3, 'M');
        var text = $('#addr').val();
        text = text.replace(/^[\s\u3000]+|[\s\u3000]+$/g, '');
        qr.addData(text);
        qr.make();
        img = qr.createImgTag(4);

        var url = 'http://blockchain.info/address/'+addr;
        $('#qr').html('<a href="'+url+'" title="'+addr+'" target="_blank">'+img+'</a>');
        $('#qr_addr').text($('#addr').val());
    }


    function calc_hash() {
        var hash = Crypto.SHA256($('#pass').val(), { asBytes: true });
        $('#hash').val(Crypto.util.bytesToHex(hash));
    }

    function onChangePass() {
        calc_hash();
        clearTimeout(timeout);
        timeout = setTimeout(generate, TIMEOUT);
    }

    function onChangeHash() {
        $('#pass').val('');
        gen_ps_reset = true;
        clearTimeout(timeout);

        if (/[^0123456789abcdef]+/i.test($('#hash').val())) {
            setErrorState($('#hash'), true, 'Erroneous characters (must be 0..9-a..f)');
            return;
        } else {
            setErrorState($('#hash'), false);
        }

        timeout = setTimeout(generate, TIMEOUT);
    }

    function onChangePrivKey() {

        clearTimeout(timeout);

        $('#pass').val('');
        gen_ps_reset = true;

        var sec = $('#sec').val();

        try { 
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
        } catch (err) {
            setErrorState($('#sec'), true, 'Invalid private key checksum');
            return;
        };

        if (version != 128) {
            setErrorState($('#sec'), true, 'Invalid private key version (must be 128)');
            return;
        } else if (payload.length < 32) {
            setErrorState($('#sec'), true, 'Invalid payload (must be 32 or 33 bytes)');
            return;
        }

        setErrorState($('#sec'), false);

        if (payload.length > 32) {
            payload.pop();
            gen_compressed = true;
            $('#compressed').button('toggle');
        } else {
            gen_compressed = false;
            $('#uncompressed').button('toggle');
        }

        $('#hash').val(Crypto.util.bytesToHex(payload));

        timeout = setTimeout(generate, TIMEOUT);
    }

    function genRandomPass() {
        var suggest = [];
        for (var i=0; i < genRandomPassLength; i++)
            suggest.push(mn_words[Math.floor(Math.random() * mn_words.length)]);
        $('#pass').val(suggest.join(' '));
        gen_from = 'pass';
        update_gen();
        calc_hash();
        generate();
        $('#pass').focus();
    }

    // --- converter ---

    var from = 'hex';
    var to = 'hex';

    function update_enc_from() {
        from = $(this).attr('id').substring(5);
        translate();
    }

    function update_enc_to() {
        to = $(this).attr('id').substring(3);
        translate();
    }

    function strToBytes(str) {
        var bytes = [];
        for (var i = 0; i < str.length; ++i)
           bytes.push(str.charCodeAt(i));
        return bytes;
    }

    function bytesToString(bytes) {
        var str = '';
        for (var i = 0; i < bytes.length; ++i)
            str += String.fromCharCode(bytes[i]);
        return str;
    }

    function isHex(str) {
        return !/[^0123456789abcdef:, ]+/i.test(str);
    }

    function isBase58(str) {
        return !/[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/.test(str);
    }

    function isBase64(str) {
        return !/[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]+/.test(str) && (str.length % 4) == 0;
    }

    function issubset(a, ssv) {
        var b = ssv.trim().split(' ');
        for (var i = 0; i < b.length; i++) {
            if (a.indexOf(b[i].toLowerCase()) == -1 
                && a.indexOf(b[i].toUpperCase()) == -1)
            return false;
        }
        return true;
    }

    function autodetect(str) {
        var enc = [];
        if (isHex(str)) 
            enc.push('hex');
        if (isBase58(str))
            enc.push('base58');
        if (issubset(mn_words, str)) 
            enc.push('mnemonic');
        if (issubset(rfc1751_wordlist, str)) 
            enc.push('rfc1751');
        if (isBase64(str))
            enc.push('base64');
        if (str.length > 0)
            enc.push('text');
        return enc;
    }

    function update_toolbar(enc) {
        var reselect = false;
        $.each($('#enc_from').children(), function() {
            var id = $(this).attr('id').substring(5);
            var disabled = (enc && enc.indexOf(id) == -1);
            if (disabled && $(this).hasClass('active')) {
                $(this).removeClass('active');
                reselect = true;
            }
            $(this).attr('disabled', disabled);
        });
        if (enc && enc.length > 0 && reselect) {
            $('#from_' + enc[0]).addClass('active');
            from = enc[0];
        }
    }

    function rot13(str) {
        return str.replace(/[a-zA-Z]/g, function(c) {
          return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);
        });
    }

    function enct(id) {
        return $('#from_'+id).text();
    }

    function translate() {

        var str = $('#src').val();

        if (str.length == 0) {
            update_toolbar(null);
            return;
        }

        text = str;

        var enc = autodetect(str);

        update_toolbar(enc);

        bytes = strToBytes(str);

        var type = '';

        if (bytes.length > 0) {
            if (from == 'base58') {
                try { 
                    var res = parseBase58Check(str); 
                    type = 'Check ver.' + res[0];
                    bytes = res[1];
                } catch (err) {
                    bytes = Bitcoin.Base58.decode(str);
                }
            } else if (from == 'hex') {
                bytes = Crypto.util.hexToBytes(str.replace(/[ :,]+/g,''));
            } else if (from == 'rfc1751') {
                try { bytes = english_to_key(str); } catch (err) { type = ' ' + err; bytes = []; };
            } else if (from == 'mnemonic') {
                bytes = Crypto.util.hexToBytes(mn_decode(str.trim()));
            } else if (from == 'base64') {
                try { bytes = Crypto.util.base64ToBytes(str); } catch (err) {}
            }

            var ver = '';
            if (to == 'base58') {
                if (bytes.length == 20 || bytes.length == 32) {
                    var addr = new Bitcoin.Address(bytes);
                    addr.version = bytes.length == 32 ? 128 : 0;
                    text = addr.toString();
                    ver = 'Check ver.' + addr.version;
                } else {
                    text = Bitcoin.Base58.encode(bytes);
                }
            } else if (to == 'hex') {
                text = Crypto.util.bytesToHex(bytes);
            } else if (to == 'text') {
                text = bytesToString(bytes);
            } else if (to == 'rfc1751') {
                text = key_to_english(bytes);
            } else if (to == 'mnemonic') {
                text = mn_encode(Crypto.util.bytesToHex(bytes));
            } else if (to == 'base64') {
                text = Crypto.util.bytesToBase64(bytes);
            } else if (to == 'rot13') {
                text = rot13(str);
            }
        }

        $('#hint_from').text(enct(from) + type + ' (' + bytes.length + ' byte' + (bytes.length == 1 ? ')' : 's)'));
        $('#hint_to').text(enct(to) + ver + ' (' + text.length + ' character' + (text.length == 1 ? ')' : 's)'));
        $('#dest').val(text);
    }

    function onChangeFrom() {
        clearTimeout(timeout);
        timeout = setTimeout(translate, TIMEOUT);
    }
    
    function onValue(id, funcgettext, funcevent) {
        $(id).bind("input keyup keydown keypress change blur", function() {
            if (funcgettext() != jQuery.data(this, "lastvalue")) {
                funcevent();
            }
            jQuery.data(this, "lastvalue", funcgettext());
        });
        $(id).bind("focus", function() {
           jQuery.data(this, "lastvalue", funcgettext());
        });
    }

    function onInput(id, func) {
        onValue(id, $(this).val, func);
    }

    // --- chain ---
    var chain_mode = 'csv';
    var addresses = [];
    var chain_range = parseInt($('#range').val());
    var chain_type = 'chain_armory';

    function onChangeMethod() {
        var id = $(this).attr('id');

        if (chain_type != id) {
            $('#seed').val('');
            $('#expo').val('');
            $('#memo').val('');
            $('#progress').text('');
            $('#chain').text('');
            chOnStop();
        }

        $('#elChange').attr('disabled', id != 'chain_electrum');

        chain_type = id;
    }

    function onChangeFormat() {
        chain_mode = $(this).attr('id');
        update_chain();
    }

    function addr_to_csv(i, r) {
        return i + ', "' + r[0] +'", "' + r[1] +'"\n';
    }

    function update_chain() {
        if (addresses.length == 0)
            return;
        var str = '';
        if (chain_mode == 'csv') {
            for (var i = 0; i < addresses.length; i++)
                str += addr_to_csv(i+1, addresses[i]);

        } else if (chain_mode == 'json') {

            var w = {};
            w['keys'] = [];
            for (var i = 0; i < addresses.length; i++)
                w['keys'].push({'addr':addresses[i][0],'sec':addresses[i][1]});
            str = JSON.stringify(w, null, 4);
        }
        $('#chain').text(str);

        chain_range = parseInt($('#range').val());
        var change = chain_type == 'chain_electrum' ? parseInt($('#elChange').val()) : 0;

        if (addresses.length >= chain_range+change)
            chOnStop();

    }

    function onChangeSeed() {
        $('#expo').val('');
        $('#progress').text('');
        chOnStop();
        $('#memo').val( mn_encode(seed) );
        clearTimeout(timeout);
        timeout = setTimeout(chain_generate, TIMEOUT);
    }

    function onChangeMemo() {
        var str =  $('#memo').val();

        if (str.length == 0) {
            chOnStop();
            return;
        }

        if (chain_type == 'chain_electrum') {
            if (issubset(mn_words, str))  {
                var seed = mn_decode(str);
                $('#seed').val(seed);
            }
        }

        if (chain_type == 'chain_armory') {
            var keys = armory_decode_keys(str);
            if (keys != null) {
                var cc = keys[1];
                var pk = keys[0];
                $('#seed').val(Crypto.util.bytesToHex(cc));
                $('#expo').val(Crypto.util.bytesToHex(pk));
            }
        }

        clearTimeout(timeout);
        timeout = setTimeout(chain_generate, TIMEOUT);
    }

    function chOnPlay() {
        var cc = Crypto.util.randomBytes(32);
        var pk = Crypto.util.randomBytes(32);

        if (chain_type == 'chain_armory') {
            $('#seed').val(Crypto.util.bytesToHex(cc));
            $('#expo').val(Crypto.util.bytesToHex(pk));
            var codes = armory_encode_keys(pk, cc);
            $('#memo').val(codes);
        }

        if (chain_type == 'chain_electrum') {
            var seed = Crypto.util.bytesToHex(pk.slice(0,16));
            //nb! electrum doesn't handle trailing zeros very well
            if (seed.charAt(0) == '0') seed = seed.substr(1);
            $('#seed').val(seed);
            var codes = mn_encode(seed);
            $('#memo').val(codes);
        }
        chain_generate();
    }

    function chOnStop() {
        Armory.stop();
        Electrum.stop();
        $('#chStop').hide();
        $('#chPlay').show();

        if (chain_type == 'chain_electrum') {
            $('#progress').text('');
        }
    }

    function onChangeRange()
    {
        if ( addresses.length==0 )
          return;
        clearTimeout(timeout);
        timeout = setTimeout(update_chain_range, TIMEOUT);
    }

    function addr_callback(r) {
        addresses.push(r);
        $('#chain').append(addr_to_csv(addresses.length,r));
    }

    function electrum_seed_update(r, seed) {
        $('#progress').text('key stretching: ' + r + '%');
        $('#expo').val(Crypto.util.bytesToHex(seed));
    }

    function electrum_seed_success(privKey) {
        $('#progress').text('');
        $('#expo').val(Crypto.util.bytesToHex(privKey));
        var addChange = parseInt($('#elChange').val());
        Electrum.gen(chain_range, addr_callback, update_chain, addChange);
    }

    function update_chain_range() {
        chain_range = parseInt($('#range').val());

        addresses = [];
        $('#chain').text('');

        if (chain_type == 'chain_electrum') {
            var addChange = parseInt($('#elChange').val());
            Electrum.stop();
            Electrum.gen(chain_range, addr_callback, update_chain, addChange);
        }

        if (chain_type == 'chain_armory') {
            var codes = $('#memo').val();
            Armory.gen(codes, chain_range, addr_callback, update_chain);
        }
    }

    function chain_generate() {
        clearTimeout(timeout);

        var seed = $('#seed').val();
        var codes = $('#memo').val();

        addresses = [];
        $('#progress').text('');
        $('#chain').text('');

        Electrum.stop();

        if (chain_type == 'chain_electrum') {
           if (seed.length == 0)
               return;
            Electrum.init(seed, electrum_seed_update, electrum_seed_success);
        }

        if (chain_type == 'chain_armory') {
            var uid = Armory.gen(codes, chain_range, addr_callback, update_chain);
            if (uid)
                $('#progress').text('uid: ' + uid);
            else
                return;
        }

        $('#chPlay').hide();
        $('#chStop').show();
    }

    // -- transactions --

    var txType = 'txBBE';

    function txListTokenAddr() {
      // ensure a token is present
      // TODO rescan(); 
      
      // clearup the list of address
      var txAddr = $('#txAddr');
      txAddr.empty();
      
      // now list addr and append public value as face value, and encoded private as used value
      // retrieve the list of existing keys for the given token serial
      storageGetKeys(function(keylist) {
          if (keylist != null) {
            for (var i = 0; i < keylist.length ; i++) {
              // append new option in the list
              txAddr.append($('<option>', {
                  text: keylist[i].address,
                  value: JSON.stringify(keylist[i])
              }));
            }
            
            // update the unspent for this address
            // TODO REACTIVATE for auto update balance and unspent txOnChangeAddr();
          }
        }
      );
    }
    
    function txGetSelectedAddr() {
      return $('#txAddr option:selected').text();
    }
    
    function txGetSelectedEncodedPrivate() {
      return JSON.parse($('#txAddr option:selected').val());
    }

    function txOnChangeSec() {
        clearTimeout(timeout);
        timeout = setTimeout(txGenSrcAddr, TIMEOUT);
    }

    function txOnChangeAddr() {
        clearTimeout(timeout);
        timeout = setTimeout(txUpdateUnspent, TIMEOUT);
        timeout = setTimeout(txUpdateBalance, TIMEOUT);
    }
    
    function txUpdateBalanceCallback(balance) {
      // convert satoshi to bitcoins
      balance = parseFloat(balance, 10)/100000000;
      $('#txBalance').val(balance);
    }
    
    function txUpdateBalance() {
        var addr = txGetSelectedAddr();
        $('#txBalance').val('Loading ...');
        
        get_json('http://blockchain.info/q/addressbalance/'+addr+'?confirmations=6', txUpdateBalanceCallback);
    }

    function txUpdateUnspentCallbackBCI(r) {
      try {
        //var r = JSON.parse(text); // already done in ajax call

        // now that we fetched raw transactions and unspent output, we can start the wallet update
        btchipUpdateWallet(txGetSelectedEncodedPrivate(), walletRawTX, r['unspent_outputs']);
        
        // serialize the wallet online
        storageSaveWallet(txGetSelectedAddr());
      } catch (e) {
        log.error(e);
        alert(e);
      }
    }

    function txUpdateWalletCallbackBBE(r) {
      try {
        //var r = JSON.parse(text); // already done in ajax call
        $('#txUnspent').val(JSON.stringify(r));
        
        var addr = txGetSelectedAddr();
        walletRawTX = r;
        
        get_json('http://blockchain.info/unspent?active=' + addr + '&confirmations=6&format=json', txUpdateUnspentCallbackBCI, alert);
        
      } catch (e) {
        log.error(e);
        alert(e);
      }
    }
    
    function txUpdateUnspentCallbackError(r) {
      $('#txUnspent').val("No unspent outputs: " + r);
    }

    function txUpdateUnspent() {
        var addr = txGetSelectedAddr();
        
        // load the wallet
        storageLoadWallet(addr, function () {
          // synchronize the wallet once loaded
          $('#txUnspent').val('Loading ...');
          get_json('http://blockexplorer.com/q/mytransactions/' + addr, txUpdateWalletCallbackBBE);
        });
    }
    

    function txOnChangeJSON() {
        var str = $('#txJSON').val();
        var sendTx = TX.fromBBE(str);
        var bytes = sendTx.serialize();
        var hex = Crypto.util.bytesToHex(bytes);
        $('#txHex').val(hex);
    }

    function txOnChangeHex() {
        var str = $('#txHex').val();
        str = str.replace(/[^0-9a-fA-f]/g,'');
        $('#txHex').val(str);
        var bytes = Crypto.util.hexToBytes(str);
        var sendTx = TX.deserialize(bytes);
        var text = TX.toBBE(sendTx);
        $('#txJSON').val(text);
    }

    function txOnAddDest() {
        var list = $(document).find('.txCC');
        var clone = list.last().clone();
        clone.find('.help-inline').empty();
        clone.find('.control-label').text('Cc');
        var dest = clone.find('#txDest');
        var value = clone.find('#txValue');
        clone.insertAfter(list.last());
        onInput(dest, txOnChangeDest);
        onInput(value, txOnChangeDest);
        dest.val('');
        value.val('');
        $('#txRemoveDest').attr('disabled', false);
        return false;
    }

    function txOnRemoveDest() {
        var list = $(document).find('.txCC');
        if (list.size() == 2)
            $('#txRemoveDest').attr('disabled', true);
        list.last().remove();
        return false;
    }

    function txSent(text) {
        alert(text ? text : 'No response!');
    }

    function txSend() {
      /*
        var txAddr = txGetSelectedAddr();
        var address = TX.getAddress();

        var r = '';
        */
        /*
        if (txAddr != address)
            r += 'Warning! Source address does not match private key.\n\n';
        */
        var tx = btchipComputeTransaction(txGetSelectedEncodedPrivate()); //$('#txHex').val();

        $('#txHex').val(tx);
        //url = 'http://bitsend.rowit.co.uk/?transaction=' + tx;
        url = 'http://blockchain.info/pushtx';
        postdata = 'tx=' + tx;
        //url = prompt(r + 'Send transaction:', url);
        if (url != null && url != "") {
            tx_fetch(url, txSent, txSent, postdata);
        }
        return false;
    }

    function txOnChangeDest() {
        var balance = parseFloat($('#txBalance').val());
        var fval = parseFloat('0'+$('#txValue').val());
        var fee = parseFloat('0'+$('#txFee').val());

        if (fval + fee > balance) {
            fee = balance - fval;
            $('#txFee').val(fee > 0 ? fee : '0.00');
        }

        //clearTimeout(timeout);
        //timeout = setTimeout(txRebuild, TIMEOUT);
    }

    function txShowUnspent() {
        var div = $('#txUnspentForm');

        if (div.hasClass('hide')) {
            div.removeClass('hide');
            $('#txShowUnspent').text('Hide Outputs');
        } else {
            div.addClass('hide');
            $('#txShowUnspent').text('Show Outputs');
        }
    }

    function txChangeType() {
        txType = $(this).attr('id');
        txUpdateUnspent();
    }

    function txOnChangeFee() {

        var balance = parseFloat($('#txBalance').val());
        var fee = parseFloat('0'+$('#txFee').val());

        var fval = 0;
        var o = txGetOutputs();
        for (i in o) {
            TX.addOutput(o[i].dest, o[i].fval);
            fval += o[i].fval;
        }

        if (fval + fee > balance) {
            fval = balance - fee;
            $('#txValue').val(fval < 0 ? 0 : fval);
        }

        if (fee == 0 && fval == balance - 0.0005) {
            $('#txValue').val(balance);
        }

        /*
        clearTimeout(timeout);
        timeout = setTimeout(txRebuild, TIMEOUT);
        */
    }

    function txGetOutputs() {
        var res = [];
        $.each($(document).find('.txCC'), function() {
            var dest = $(this).find('#txDest').val();
            var fval = parseFloat('0' + $(this).find('#txValue').val());
            res.push( {"dest":dest, "fval":fval } );
        });
        return res;
    }

    

    // -- sign --

    function updateAddr(from, to) {
        var sec = from.val();
        var addr = '';
        var eckey = null;
        var compressed = false;
        try {
            var res = parseBase58Check(sec); 
            var version = res[0];
            var payload = res[1];
            if (payload.length > 32) {
                payload.pop();
                compressed = true;
            }
            eckey = new Bitcoin.ECKey(payload);
            var curve = getSECCurveByName("secp256k1");
            var pt = curve.getG().multiply(eckey.priv);
            eckey.pub = getEncoded(pt, compressed);
            eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(eckey.pub);
            addr = eckey.getBitcoinAddress();
            setErrorState(from, false);
        } catch (err) {
            setErrorState(from, true, "Bad private key");
        }
        to.val(addr);
        return {"key":eckey, "compressed":compressed};
    }

    function sgGenAddr() {
        updateAddr($('#sgSec'), $('#sgAddr'));
    }

    function sgOnChangeSec() {
        $('#sgSig').val('');
        clearTimeout(timeout);
        timeout = setTimeout(sgGenAddr, TIMEOUT);
    }

    function sgSign() {
        var message = $('#sgMsg').val();
        var p = updateAddr($('#sgSec'), $('#sgAddr'));
        var sig = sign_message(p.key, message, p.compressed);
        $('#sgSig').val(sig);
    }

    function sgOnChangeMsg() {
        $('#sgSig').val('');
        clearTimeout(timeout);
        timeout = setTimeout(sgUpdateMsg, TIMEOUT);
    }

    function sgUpdateMsg() {
        $('#vrMsg').val($('#sgMsg').val());
    }

    // -- verify --

    function vrVerify() {
        var message = $('#vrMsg').val();
        var sig = $('#vrSig').val();
        var res = verify_message(sig, message);

        if (res) {
            var href = 'https://blockchain.info/address/' + res;
            var a = '<a href=' + href + ' target=_blank>' + res + '</a>';
            $('#vrRes').html('Verified to: ' + a);
        } else {
            $('#vrRes').text('false');
        }
        return false;
    }

    function vrClearRes() {
        $('#vrRes').text('');
    }
    
    function storageGetInstance() {
      /*
      var url = "http://example.com";
      var ios = Components.classes["@mozilla.org/network/io-service;1"]
                .getService(Components.interfaces.nsIIOService);
      var ssm = Components.classes["@mozilla.org/scriptsecuritymanager;1"]
                .getService(Components.interfaces.nsIScriptSecurityManager);
      var dsm = Components.classes["@mozilla.org/dom/storagemanager;1"]
                .getService(Components.interfaces.nsIDOMStorageManager);
      
      var uri = ios.newURI(url, "", null);
      var principal = ssm.getCodebasePrincipal(uri);
      var storage = dsm.getLocalStorageForPrincipal(principal, "");
      */
      
      return localStorage;
    }
    
    // private keys
    function storageGet(key, callback) {
      var value = storageGetInstance().getItem(key);
      // localstorage is not asynchronous ... but keep the model in case remote storage
      callback(value);
    }
    
    function storageSet(key, val, callback) {
      storageGetInstance().setItem(key, val);
    }
    
    function storageClear(key, callback) {
      storageGetInstance().setItem(key, '');
    }
    
    function storageGetJSONList(basekey, callback) {
      storageGet(basekey, function(value) {
          var count = value;
          
          // if list empty, create new list
          if (count == null) {
            callback([]);
          }
          else {
            // enjoy the async iterator, featuring stack recursion
            var list = [];
            var i = 0;
            var iter = function (value) {
              
              // value fetched
              list.push(JSON.parse(value));
              
              // no more keys to fetch, call the callback
              i+=1;
              if (i >= count) {
                callback(list);
              }
              else {
                storageGet(basekey+"_"+i, iter);
              }
            };
            
            storageGet(basekey+"_"+i, iter);
          }
        }
      ); 
    }
    
    function storageAddJSONList(basekey, value, callback) {
      storageGet(basekey, function(count, key) {
          // if list empty, create new list
          if (count == null) {
            count = 0;
          }
          else {
            // check if already in the list
          }
          
          // store the key
          storageSet(basekey+"_"+count, JSON.stringify(value));
          
          // increase the number of keys
          count=parseInt(count,10)+1;
          
          // store back the existing key list for the token serial
          storageSet(basekey, count);          
        }
      ); 
    }
    
    function storageSetJSONList(basekey, list, callback) {
      // kill list content before updating it
      storageSet(basekey, 0);

      // store the key
      for (var count=0;count<list.length;count++) {
        storageSet(basekey+"_"+count, JSON.stringify(list[count]));
      }
      
      // store back the existing key list for the token serial
      storageSet(basekey, list.length);
    }
    
    function storageAddKey(keyBlob, callback) {
      storageAddJSONList(tokenSerial+'_k', keyBlob, callback);
    }
    
    function storageGetKeys(callback) {
      storageGetJSONList(tokenSerial+'_k', callback);
    }
    
    function storageLoadWallet(address, callback) {
      storageGetJSONList(tokenSerial+'_w_'+address, function (list) {wallet = list; callback();});
    }
    
    function storageSaveWallet(address, callback) {
      storageSetJSONList(tokenSerial+'_w_'+address, wallet, callback);
    }
    
    // TODO function storageDelKey
    
    function keysImportGenKeyCallback (privblob) {
        // insert key in openkeyval key list
        storageAddKey(privblob);
        
        // display the generated address
        $('#keysGenerated').val(privblob['address']);
        
        // append newly generated key to the combo list
        var txAddr = $('#txAddr');
        txAddr.append($('<option>', {
            text: privblob['address'],
            value: JSON.stringify(privblob)
        }));
        
        // emptify the priv key slot, to avoid too easy eavesdropping (f)
        $('#keysPrivAddr').val('');
    }
    
    function keysGenAddr() {
      $('#keysGenerated').val("Generating...");
      btchipGenerateKey(keysImportGenKeyCallback);
    }
    
    function keysImportAddr() {
      var privWIF = $('#keysPrivAddr').val();
      $('#keysGenerated').val("Importing...");
      btchipImportWIF(privWIF, keysImportGenKeyCallback);
    }
    
    /**
     * WARNING, if no backup then all private keys are lost
     */
    function keysDelAllAddr() {
      var storageKey = tokenSerial+'_k';
      storageClear(storageKey);
    }

    $(document).ready( function() {

        if (window.location.hash)
            $('#tab-' + window.location.hash.substr(1)).tab('show');

        $('a[data-toggle="tab"]').on('shown', function (e) {
            window.location.hash = $(this).attr('href');
        });

/*
        // generator

        onInput('#pass', onChangePass);
        onInput('#hash', onChangeHash);
        onInput('#sec', onChangePrivKey);

        $('#from_pass').click(update_gen_from);
        $('#from_hash').click(update_gen_from);
        $('#from_sec').click(update_gen_from);

        $('#random').click(gen_random);

        $('#uncompressed').click(update_gen_compressed);
        $('#compressed').click(update_gen_compressed);
        gen_compressed = $('#compressed').hasClass('active');

        $('#genRandomPass').click(genRandomPass);
        genRandomPass();
        genUpdateLabel();
*/
/*
        // chains

        $('#chPlay').click(chOnPlay);
        $('#chStop').click(chOnStop);

        $('#csv').click(onChangeFormat);
        $('#json').click(onChangeFormat);

        $('#chain_armory').click(onChangeMethod);
        $('#chain_electrum').click(onChangeMethod);

        onInput($('#range'), onChangeRange);
        onInput($('#seed'), onChangeSeed);
        onInput($('#memo'), onChangeMemo);
        onInput($('#elChange'), onChangeRange);
*/
        // transactions

//        $('#txSec').val(tx_sec);
//        $('#txAddr').val(tx_addr);
//        $('#txDest').val(tx_dest);


        $('#txBalance').val('');

        
        $('#txListTokenAddr').click(txListTokenAddr);
        $('#txGetUnspent').click(txUpdateUnspent);

        $('#txBCI').click(txChangeType);
        $('#txBBE').click(txChangeType);

        onValue($('#txAddr'), txGetSelectedAddr, txOnChangeAddr);
        onInput($('#txDest'), txOnChangeDest);
        onInput($('#txValue'), txOnChangeDest);
        onInput($('#txFee'), txOnChangeFee);

        $('#txAddDest').click(txOnAddDest);
        $('#txRemoveDest').click(txOnRemoveDest);
        $('#txSend').click(txSend);

        // private keys
        $('#keysGenAddr').click(keysGenAddr);
        $('#keysImportAddr').click(keysImportAddr);
        $('#keysDelAllAddr').click(keysDelAllAddr);
        
/*
        // converter

        onInput('#src', onChangeFrom);
        $("body").on("click", "#enc_from .btn", update_enc_from);
        $("body").on("click", "#enc_to .btn", update_enc_to);

        // sign
        $('#sgSec').val('5JeWZ1z6sRcLTJXdQEDdB986E6XfLAkj9CgNE4EHzr5GmjrVFpf');
        $('#sgAddr').val('17mDAmveV5wBwxajBsY7g1trbMW1DVWcgL');
        $('#sgMsg').val("C'est par mon ordre et pour le bien de l'Etat que le porteur du présent a fait ce qu'il a fait.");

        onInput('#sgSec', sgOnChangeSec);
        onInput('#sgMsg', sgOnChangeMsg);

        $('#sgSign').click(sgSign);
        $('#sgForm').submit(sgSign);

        // verify
        $('#vrMsg').val($('#sgMsg').val());

        onInput('#vrAddr', vrClearRes);
        onInput('#vrMsg', vrClearRes);
        onInput('#vrSig', vrClearRes);
        $('#vrVerify').click(vrVerify);
*/
    });
})(jQuery);
