require('Card');
require('GPSecurityDomain');
//require('PlugupV1');

var BitcoinBasic = Class.extend(PlugupV2, {
	/**@lends BitcoinBasic.prototype */
	
	/**
	 * @class Communication with Bitcoin application over a {@link Card} 
	 * @param {Object} @Card implementing the Bitcoin
	 * @constructs
	 */
	initialize : function(card) {
		if (!(card instanceof Card) && !(card instanceof GPSecurityDomain)) {
			throw "Invalid card";
		}
		this.card = card;
	},
	
	generateKeypair : function(privateKeyEncryptionVersion, signatureKeyVersion, flags, curveFid, authorizedAddressKeyVersion, authorizedAddressBitcoinVersion) {
		var resultArray;
		var authorizedAddressSize;
		var p1 = 0x00;
		if (typeof curveFid == "undefined") {
			curveFid = 0xb1c0;
		}
		if (typeof flags == "undefined") {
			flags = 0;
		}
		if (typeof privateKeyEncryptionVersion == "undefined") {
			p1 |= 0x10;
		}
		var data = Convert.toHexByte(privateKeyEncryptionVersion) + Convert.toHexByte(signatureKeyVersion) + Convert.toHexByte(flags) + Convert.toHexShort(curveFid);
		if (typeof authorizedAddressKeyVersion != "undefined") {
			if (typeof authorizedAddressBitcoinVersion == "undefined") {
				authorizedAddressBitcoinVersion = 0x01;
			}
			data += Convert.toHexByte(authorizedAddressKeyVersion) + Convert.toHexByte(authorizedAddressBitcoinVersion);
			p1 |= 0x01;
		}
		data = new ByteString(data, HEX);
		var result = this.card.sendApdu(0xe0, 0x20, p1, 0x00, data, [0x9000]);
		var publicSize = result.byteAt(0);
		var privateSize = result.byteAt(1 + publicSize);
		var diversificationOffset = 1 + publicSize + 1 + privateSize;
		resultArray = [ result.bytes(1, publicSize), result.bytes(1 + publicSize + 1, privateSize), result.bytes(diversificationOffset, 32), result.bytes(diversificationOffset + 32, 8) ];
		if (typeof authorizedAddressKeyVersion != "undefined") {
			authorizedAddressSize = result.byteAt(diversificationOffset + 32 + 8);
			resultArray.push(result.bytes(diversificationOffset + 32 + 8 + 1, authorizedAddressSize));			
		}
		return resultArray;
	},

	generateKeypairFromData : function(privateKeyEncryptionVersion, signatureKeyVersion, privateComponent, prepareFlags, flags, curveFid, deriveKeyVersion, authorizedAddressKeyVersion, authorizedAddressBitcoinVersion) {
		var resultArray;
		var authorizedAddressSize;
		var p1 = 0x80;
		if (typeof curveFid == "undefined") {
			curveFid = 0xb1c0;
		}
		if (typeof flags == "undefined") {
			flags = 0;
		}
		if (typeof deriveKeyVersion == "undefined") {
			deriveKeyVersion = 0;
		}
		else {
			p1 |= 0x08;
		}
		if (typeof prepareFlags != "undefined") {
			p1 |= parseInt(prepareFlags);
		}
		var data = Convert.toHexByte(privateKeyEncryptionVersion) + Convert.toHexByte(signatureKeyVersion) + Convert.toHexByte(flags) + Convert.toHexShort(curveFid);
		if (typeof authorizedAddressKeyVersion != "undefined") {
			if (typeof authorizedAddressBitcoinVersion == "undefined") {
				authorizedAddressBitcoinVersion = 0x01;
			}
			data += Convert.toHexByte(authorizedAddressKeyVersion) + Convert.toHexByte(authorizedAddressBitcoinVersion);
			p1 |= 0x01;
		}		
		data = new ByteString(data, HEX);
		data = data.concat(privateComponent);
		var result = this.card.sendApdu(0xe0, 0x20, p1, deriveKeyVersion, data, [0x9000]);
		var publicSize = result.byteAt(0);
		var privateSize = result.byteAt(1 + publicSize);
		var diversificationOffset = 1 + publicSize + 1 + privateSize;
		resultArray = [ result.bytes(1, publicSize), result.bytes(1 + publicSize + 1, privateSize), result.bytes(diversificationOffset, 32), result.bytes(diversificationOffset + 32, 8) ];
		if (typeof authorizedAddressKeyVersion != "undefined") {
			authorizedAddressSize = result.byteAt(diversificationOffset + 32 + 8);
			resultArray.push(result.bytes(diversificationOffset + 32 + 8 + 1, authorizedAddressSize));			
		}
		return resultArray;
	},

	queryOperationMode : function(signatureKeyVersion) {
		var result = this.card.sendApdu(0xe0, 0x24, 0x00, 0x00, new ByteString(Convert.toHexByte(signatureKeyVersion), HEX), [0x9000]);
		return result;
	},

	setOperationMode : function(mode, persistentChange, signatureKeyVersion) {
		var result = this.card.sendApdu(0xe0, 0x24, mode, (persistentChange ? 0x00 : 0x80), new ByteString(Convert.toHexByte(signatureKeyVersion), HEX), [0x9000]);
		return result;
	},

	getPublicKey: function(privateKeyEncryptionVersion, encryptedPrivateKey) {
		var data = "";
		data = data + Convert.toHexByte(privateKeyEncryptionVersion);
		data = new ByteString(data, HEX);
		data = data.concat(encryptedPrivateKey);
		return this.card.sendApdu(0xe0, 0x26, 0x00, 0x00, data, [0x9000]);	
	},

	encodeAddress : function(address, authorizedAddressKey, binaryFormat) {
		var data = new ByteString(Convert.toHexByte(authorizedAddressKey) + Convert.toHexByte(address.length), HEX);
		if (binaryFormat) {
			data = data.concat(authorizedAddressKey);
		}
		else {
			data = data.concat(new ByteString(address, ASCII));
		}
		var result = this.card.sendApdu(0xe0, 0x22, (binaryFormat ? 0x80 : 0x00), 0x00, data);
		return result;
	},
	
	ecdsaSignImmediate : function(privateKeyEncryptionVersion, encryptedPrivateKey, hash) {
		var data = "";
		data = data + Convert.toHexByte(privateKeyEncryptionVersion);
		data = data + Convert.toHexByte(encryptedPrivateKey.length);
		data = new ByteString(data, HEX);
		data = data.concat(encryptedPrivateKey);
		data = data.concat(hash);
		return this.card.sendApdu(0xe0, 0x40, 0x00, 0x00, data, [0x9000]);
	},

	ecdsaVerifyImmediate : function(publicKey, hash, signature, curveFid) {
		if (typeof curveFid == 'undefined') {
			curveFid = 0xb1c0;
		}
		var data = new ByteString(Convert.toHexShort(curveFid) + Convert.toHexByte(publicKey.length), HEX);
		data = data.concat(publicKey);
		data = data.concat(new ByteString(Convert.toHexByte(hash.length), HEX));
		data = data.concat(hash);
		data = data.concat(signature);
		return this.card.sendApdu(0xe0, 0x40, 0x80, 0x00, data, [0x9000]);		
	},

	getTrustedInputRaw: function(firstRound, keysetVersion, indexLookup, transactionData) {
		var data = "";
		if (firstRound) {
			data = data + Convert.toHexByte(keysetVersion);
			data = data + Convert.toHexByte((indexLookup >> 24) & 0xff) + Convert.toHexByte((indexLookup >> 16) & 0xff) + Convert.toHexByte((indexLookup >> 8) & 0xff) + Convert.toHexByte(indexLookup & 0xff);
			data = new ByteString(data, HEX).concat(transactionData);
		}
		else {
			data = transactionData;
		}
		return this.card.sendApdu(0xe0, 0x42, (firstRound ? 0x00 : 0x80), 0x00, data, [0x9000]);
	},

	getTrustedInput: function(keysetVersion, indexLookup, transaction) {
		var bufferedData = new ByteString("", HEX);
		var firstSend = true;
		var previousResult;
		var concatOrFlush = function(parent, data) {
			if ((typeof data == "undefined") || ((bufferedData.length + data.length) > 250)) {
				if (bufferedData.length == 0) {
					return previousResult;
				}
				// Needs to flush
				if (firstSend) {
					previousResult = parent.getTrustedInputRaw(true, keysetVersion, indexLookup, bufferedData);
					firstSend = false;
				}
				else {
                                        previousResult = parent.getTrustedInputRaw(false, keysetVersion, indexLookup, bufferedData);
					//previousResult = parent.getTrustedInputRaw(false, undefined, undefined, bufferedData);
				}
				if (typeof data != "undefined") {
					bufferedData = data;
				}
				else {
					bufferedData = new ByteString("", HEX);
				}
			}
			else {
				bufferedData = bufferedData.concat(data);
			}
			return previousResult;
		};		 
		var data = transaction['version'].concat(this.createVarint(transaction['inputs'].length));
		concatOrFlush(this, data);
		for (var i=0; i<transaction['inputs'].length; i++) {
			var input = transaction['inputs'][i];
			data = input['prevout'].concat(this.createVarint(input['script'].length));
			data = data.concat(input['script']).concat(input['sequence']);
			concatOrFlush(this, data);
		}
		data = this.createVarint(transaction['outputs'].length);
		concatOrFlush(this, data);
		for (var i=0; i<transaction['outputs'].length; i++) {
			var output = transaction['outputs'][i];
			data = output['amount'];
			data = data.concat(this.createVarint(output['script'].length).concat(output['script']));
			concatOrFlush(this, data);
		}
		data = transaction['locktime'];
		concatOrFlush(this, data);
		return concatOrFlush(this);
	},

	startUntrustedHashTransactionInputRaw: function(newTransaction, firstRound, transactionFid, transactionData) {
		var data = "";
		if (newTransaction && firstRound) {
			data = data + Convert.toHexShort(transactionFid);
			data = new ByteString(data, HEX).concat(transactionData);
		}
		else {
			data = transactionData;
		}
		return this.card.sendApdu(0xe0, 0x44, (firstRound ? 0x00 : 0x80), (newTransaction ? 0x00 : 0x80), data, [0x9000]);
	},

	startUntrustedHashTransactionInput: function(newTransaction, transactionFid, transaction, trustedInputs, trustedInputKeys) {
		var bufferedData = new ByteString("", HEX);
		var firstSend = true;
		var concatOrFlush = function(parent, data) {
			if ((typeof data == "undefined") || ((bufferedData.length + data.length) > 255)) {
				// Needs to flush
				if (firstSend) {
					parent.startUntrustedHashTransactionInputRaw(newTransaction, true, transactionFid, bufferedData);
					firstSend = false;
				}
				else {
					parent.startUntrustedHashTransactionInputRaw(newTransaction, false, undefined, bufferedData);
				}
				if (typeof data != "undefined") {
					bufferedData = data;
				}
				else {
					bufferedData = new ByteString("", HEX);
				}
			}
			else {
				bufferedData = bufferedData.concat(data);
			}
		};		 
		var data = transaction['version'].concat(this.createVarint(transaction['inputs'].length));
		concatOrFlush(this, data);		
		for (var i=0; i<transaction['inputs'].length; i++) {
			var input = transaction['inputs'][i];
			var inputKey;
			if (trustedInputKeys instanceof Array) {
				inputKey = trustedInputKeys[i];
			}
			else {
				inputKey = trustedInputKeys;
			}
			data = new ByteString(Convert.toHexByte(inputKey) + Convert.toHexByte(trustedInputs[i].length), HEX);
			data = data.concat(trustedInputs[i]).concat(this.createVarint(input['script'].length));
			concatOrFlush(this, data);			
			data = input['script'].concat(input['sequence']);
			concatOrFlush(this, data);			
                }
                concatOrFlush(this);
	},

	hashOutputInternal: function(outputType, changeKeyVersion, changeKey, outputAddress, amount, fees, authorizedAddressKeyVersion) {
		if (typeof changeKey == "undefined") {
			changeKey = new ByteString("", HEX);
		}
		var data = new ByteString(Convert.toHexByte(changeKeyVersion) + Convert.toHexByte(outputAddress.length), HEX);
		data = data.concat(outputAddress);
		data = data.concat(new ByteString(Convert.toHexByte(changeKey.length), HEX)).concat(changeKey);
		data = data.concat(amount).concat(fees);
		var outData = this.card.sendApdu(0xe0, 0x46, outputType, authorizedAddressKeyVersion, data, [0x9000]);
		var result = {};
		var scriptDataLength = outData.byteAt(0);
		var authorizationLength = outData.byteAt(1 + scriptDataLength);
		result['scriptData'] = outData.bytes(1, scriptDataLength);
		if (authorizationLength != 0) {
			result['authorizationData'] = outData.bytes(1 + scriptDataLength + 1, authorizationLength);
		}
		return result;
	}, 

	hashOutputBinary: function(changeKeyVersion, changeKey, outputAddress, amount, fees) {
		return this.hashOutputInternal(0x01, changeKeyVersion, changeKey, outputAddress, amount, fees, 0x00);
	},

	hashOutputBase58: function(changeKeyVersion, changeKey, outputAddress, amount, fees) {
		return this.hashOutputInternal(0x02, changeKeyVersion, changeKey, outputAddress, amount, fees, 0x00);
	},

	hashOutputAuthorizedAddress: function(changeKeyVersion, changeKey, keysetAuthorizedAddress, outputAddress, amount, fees) {
		return this.hashOutputInternal(0x03, changeKeyVersion, changeKey, outputAddress, amount, fees, keysetAuthorizedAddress);
	},

	signTransaction: function(keysetVersion, encryptedPrivateKey, transactionAuthorizationKeysetVersion, transactionAuthorization, lockTime, sigHashType) {
		if (typeof transactionAuthorization == "undefined") {
			transactionAuthorization = new ByteString("", HEX);
			transactionAuthorizationKeysetVersion = 0x00;
		}
		if (typeof lockTime == "undefined") {
			lockTime = BitcoinBasic.DEFAULT_LOCKTIME;
		}
		if (typeof sigHashType == "undefined") {
			sigHashType = BitcoinBasic.SIGHASH_ALL;
		}
		var data = new ByteString(Convert.toHexByte(keysetVersion) + Convert.toHexByte(encryptedPrivateKey.length), HEX);
		data = data.concat(encryptedPrivateKey);
		data = data.concat(new ByteString(Convert.toHexByte(transactionAuthorizationKeysetVersion) + Convert.toHexByte(transactionAuthorization.length), HEX))
		data = data.concat(transactionAuthorization);
		data = data.concat(lockTime);
		data = data.concat(new ByteString(Convert.toHexByte(sigHashType), HEX));
		return this.card.sendApdu(0xe0, 0x48, 0x00, 0x00, data, [0x9000]);
	},

	createInputScript: function(publicKey, signatureWithHashtype) {
		var data = new ByteString(Convert.toHexByte(signatureWithHashtype.length), HEX).concat(signatureWithHashtype);	
		data = data.concat(new ByteString(Convert.toHexByte(publicKey.length), HEX)).concat(publicKey);
		return data;
	},

	createPaymentTransaction: function(inputs, associatedKeysets, transactionFid, trustedInputKeyVersion, changePrivateKeyVersion, changePrivateKey, outputAddress, amount, fees, lockTime, sighashType, keysetAuthorizedAddress, authorizationKeysetVersion, authorization, resumeData) {
		// Inputs are provided as arrays of [transaction, output_index, (optional trusted input)] 
		// Or {"trustedInput":, "outputScript":} objects
		// associatedKeysets are provided as arrays of [public_key, keyset_version, encrypted_keyset]
		var defaultVersion = new ByteString("01000000", HEX);
		var defaultSequence = new ByteString("FFFFFFFF", HEX);
		var trustedInputs = [];
		var regularOutputs = [];
		var signatures = [];
		var firstRun = true;
		var scriptData;
		var resuming = (typeof authorization != "undefined");
		
		if (typeof lockTime == "undefined") {
			lockTime = BitcoinBasic.DEFAULT_LOCKTIME;
		}
		//if (typeof sigHashType == "undefined") {
			var sigHashType = BitcoinBasic.SIGHASH_ALL;
		//}
		for (var i=0; i<inputs.length; i++) {
			if (!resuming) {
				var currentTrustedInput;
				if (inputs[i] instanceof Array) {
					if (inputs[i].length > 2) {
						currentTrustedInput = inputs[i][2];
					}
					else {
						currentTrustedInput = this.getTrustedInput(trustedInputKeyVersion, inputs[i][1], inputs[i][0]);
					}
				}
				else {
					currentTrustedInput = new ByteString(inputs[i]['trustedInput'], HEX);
				}
				trustedInputs.push(currentTrustedInput);
			}
			if (inputs[i] instanceof Array) {
				regularOutputs.push(inputs[i][0].outputs[inputs[i][1]]);
			}
			else {
				var outputItem = {};
				outputItem['script'] = new ByteString(inputs[i]['outputScript'], HEX);
				regularOutputs.push(outputItem);
			}
		}
		if (resuming) {
			trustedInputs = resumeData['trustedInputs'];
		}
		// Pre-build the target transaction
		var targetTransaction = {};
		targetTransaction['version'] = defaultVersion;
		targetTransaction['inputs'] = [];
		for (var i=0; i<inputs.length; i++) {
			var tmpInput = {};
			tmpInput['script'] = new ByteString("", HEX);
			tmpInput['sequence'] = defaultSequence;
			targetTransaction['inputs'].push(tmpInput);
		}

		// Sign each input 
		for (var i=0; i<inputs.length; i++) {
			targetTransaction['inputs'][i]['script'] = regularOutputs[i]['script'];			
			var resultHash;			
			if (!((i == 0) && resuming)) {
				this.startUntrustedHashTransactionInput(firstRun, transactionFid, targetTransaction, trustedInputs, trustedInputKeyVersion);			
				if (typeof keysetAuthorizedAddress == "undefined") {
					resultHash = this.hashOutputBase58(changePrivateKeyVersion, changePrivateKey, outputAddress, amount, fees);			
				}
				else {
					resultHash = this.hashOutputAuthorizedAddress(changePrivateKeyVersion, changePrivateKey, keysetAuthorizedAddress, outputAddress, amount, fees);
				}
				if (resultHash['scriptData'].length != 0) {
					scriptData = resultHash['scriptData'];
				}
				if ((typeof resultHash['authorizationData'] != "undefined") && 
				    (typeof authorization == "undefined")) {
					var tmpResult = {};
					tmpResult['authorizationData'] = resultHash['authorizationData'];
					tmpResult['scriptData'] = scriptData;
					tmpResult['trustedInputs'] = trustedInputs;
					return tmpResult;
				}
			}
			else {
				if (i == 0) {
					scriptData = resumeData['scriptData'];
				}
			}
			signatures.push(this.signTransaction(associatedKeysets[i][2], associatedKeysets[i][1], authorizationKeysetVersion, authorization));
			targetTransaction['inputs'][i]['script'] = new ByteString("", HEX);			
			if (firstRun) {
				firstRun = false;
			}
		}
		// Populate the final input scripts
		for (var i=0; i<inputs.length; i++) {
			var tmpScriptData = new ByteString(Convert.toHexByte(signatures[i].length), HEX);
			tmpScriptData = tmpScriptData.concat(signatures[i]);
			tmpScriptData = tmpScriptData.concat(new ByteString(Convert.toHexByte(associatedKeysets[i][0].length), HEX));
			tmpScriptData = tmpScriptData.concat(associatedKeysets[i][0]);
			targetTransaction['inputs'][i]['script'] = tmpScriptData;
			targetTransaction['inputs'][i]['prevout'] = trustedInputs[i].bytes(4, 0x24);
		}
		var result = this.serializeTransaction(targetTransaction);
		result = result.concat(scriptData);
		result = result.concat(this.reverseBytestring(lockTime));
		return result;

	},

	serializeTransaction: function(transaction) {
		var data = transaction['version'].concat(this.createVarint(transaction['inputs'].length));
		for (var i=0; i<transaction['inputs'].length; i++) {
			var input = transaction['inputs'][i];
			data = data.concat(input['prevout'].concat(this.createVarint(input['script'].length)));
			data = data.concat(input['script']).concat(input['sequence']);
		}
		if (typeof transaction['outputs'] != "undefined") {
			data = data.concat(this.createVarint(transaction['outputs'].length));
			for (var i=0; i<transaction['outputs'].length; i++) {
				var output = transaction['outputs'][i];
				data = data.concat(output['amount']);
				data = data.concat(this.createVarint(output['script'].length).concat(output['script']));
			}
			data = data.concat(transaction['locktime']);
		}
		return data;
	},

	getVarint : function(data, offset) {
		if (data.byteAt(offset) < 0xfd) {
			return [ data.byteAt(offset), 1 ];
		}
		if (data.byteAt(offset) == 0xfd) {
			return [ ((data.byteAt(offset + 2) << 8) + data.byteAt(offset + 1)), 3 ];
		}
		if (data.byteAt(offset) == 0xfe) {
			return [ ((data.byteAt(offset + 4) << 24) + (data.byteAt(offset + 3) << 16) + 
				  (data.byteAt(offset + 2) << 8) + data.byteAt(offset + 1)), 5 ];
		}
	},

	reverseBytestring : function(value) {
		var result = "";
		for (var i=0; i<value.length; i++) {
			result = result + Convert.toHexByte(value.byteAt(value.length - 1 - i));
		}
		return new ByteString(result, HEX);
	},

	createVarint : function(value) {
		if (value < 0xfd) {
			return new ByteString(Convert.toHexByte(value), HEX);
		}
		if (value <= 0xffff) {
			return new ByteString("fd" + Convert.toHexByte(value & 0xff) + Convert.toHexByte((value >> 8) & 0xff), HEX);
		}
		return new ByteString("fe" + Convert.toHexByte(value & 0xff) + Convert.toHexByte((value >> 8) & 0xff) + Convert.toHexByte((value >> 16) & 0xff) + Convert.toHexByte((value >> 24) & 0xff));
	},

	splitTransaction: function(transaction) {
		var result = {};
		var inputs = [];
		var outputs = [];
		var offset = 0;
		var version = transaction.bytes(offset, 4);
		offset += 4;
		var varint = this.getVarint(transaction, offset);
		var numberInputs = varint[0];
		offset += varint[1];
		for (var i=0; i<numberInputs; i++) {
			var input = {};
			input['prevout'] = transaction.bytes(offset, 36);
			offset += 36;
			varint = this.getVarint(transaction, offset);
			offset += varint[1];
			input['script'] = transaction.bytes(offset, varint[0]);
			offset += varint[0];
			input['sequence'] = transaction.bytes(offset, 4);
			offset += 4;
			inputs.push(input);
		}		
		varint = this.getVarint(transaction, offset);
		var numberOutputs = varint[0];
		offset += varint[1];
		for (var i=0; i<numberOutputs; i++) {
			var output = {};
			output['amount'] = transaction.bytes(offset, 8);
			offset += 8;
			varint = this.getVarint(transaction, offset);
			offset += varint[1];
			output['script'] = transaction.bytes(offset, varint[0]);
			offset += varint[0];
			outputs.push(output);
		}
		var locktime = transaction.bytes(offset, 4);
		result['version'] = version;
		result['inputs'] = inputs;
		result['outputs'] = outputs;
		result['locktime'] = locktime;
		return result;
	},

	getU32LE: function(number) {
		var result = new ByteString("", HEX);
		result += Convert.toHexByte(number & 0xff);
		result += Convert.toHexByte((number >> 8) & 0xff);
		result += Convert.toHexByte((number >> 16) & 0xff);
		result += Convert.toHexByte((number >> 24) & 0xff);
		return new ByteString(result, HEX);
	},
        
	splitTransactionBlockExplorer: function(transaction) {
		var result = {};
		var inputs = [];
		var outputs = [];
		for (var i=0; i<transaction['vin_sz']; i++) {
			var input = {};
			var prevout = this.reverseBytestring(new ByteString(transaction['in'][i]['prev_out']['hash'], HEX));
			prevout = prevout.concat(this.getU32LE(transaction['in'][i]['prev_out']['n']));
			input['prevout'] = prevout;
                        input['prevout_hex'] = prevout.toStringIE(HEX);
			var scriptData = transaction['in'][i].scriptSig.split(" ");
			var script = Convert.toHexByte(scriptData[0].length / 2) + scriptData[0] + 
						 Convert.toHexByte(scriptData[1].length / 2) + scriptData[1];
			input['script'] = new ByteString(script, HEX);
                        input['script_hex'] = new ByteString(script, HEX).toStringIE(HEX);
                        input['address'] = transaction['in'][i]['address'];
			input['sequence'] = new ByteString("FFFFFFFF", HEX);
			inputs.push(input);
		}
		for (var i=0; i<transaction['vout_sz']; i++) {
			var output = {};
			output['amount'] = this.reverseBytestring(this.amountStringToBytestring(transaction['out'][i]['value']));
                        output['amount_hex'] = output['amount'].toStringIE(HEX);
			var scriptItems = transaction['out'][i]['scriptPubKey'].split(" ");
			if ((scriptItems[0] != "OP_DUP") || (scriptItems[1] != "OP_HASH160") || (scriptItems[3] != "OP_EQUALVERIFY") || (scriptItems[4] != "OP_CHECKSIG")) {
				throw "Invalid output script format for output " + i;
			}
			output['script'] = BitcoinBasic.TRANSACTION_START.concat(new ByteString(scriptItems[2], HEX)).concat(BitcoinBasic.TRANSACTION_END);
                        output['script_hex'] = output['script'].toStringIE(HEX);
			outputs.push(output);
		}
		result['version'] = this.getU32LE(transaction['ver']);
                result['version_hex'] = result['version'].toStringIE(HEX);
		result['inputs'] = inputs;
		result['outputs'] = outputs;
		result['locktime'] = this.getU32LE(transaction['lock_time']);
                // store the hash the same way as in unspent outputs of BCI
                result['hash'] = this.reverseBytestring(new ByteString(transaction['hash'], HEX)).toStringIE(HEX);
		return result;	
	},

	displayTransactionDebug: function(transaction) {
		alert("version " + transaction['version'].toStringIE(HEX));
		for (var i=0; i<transaction['inputs'].length; i++) {
			var input = transaction['inputs'][i];
			alert("input " + i + " prevout " + input['prevout'].toStringIE(HEX) + " script " + input['script'].toStringIE(HEX) + " sequence " + input['sequence'].toStringIE(HEX)); 
		}
		for (var i=0; i<transaction['outputs'].length; i++) {
			var output = transaction['outputs'][i];
			alert("output " + i + " amount " + output['amount'].toStringIE(HEX) + " script " + output['script'].toStringIE(HEX));
		}
		alert("locktime " + transaction['locktime'].toStringIE(HEX));
	},

	amountStringToBytestring : function(amount) { // needs BitcoinUtils.js, jsbn.js, jsbn2.js
		var value = Bitcoin.Util.parseValue(amount).toByteArrayUnsigned();
		var result = "";
		for (var i=0; i<value.length; i++) {
        		result += Convert.toHexByte(value[i]);
		}
		while (result.length != 16) {
        		result = "00" + result;
		}
		return new ByteString(result, HEX);
	},
        
        parseTransaction : function(rawTransactions) {
            var transaction;
            var transactionData = rawTransactions;
            var binaryTransaction = true;
            try {
                transactionData = new ByteString(transactionData, HEX);
            }
            catch(e) {
                binaryTransaction = false;
            }
            
            if (transactionData.length == 0) {
                binaryTransaction = false;
                transactionData = rawTransactions;
            }
            try {
                if (!binaryTransaction) {
                    transaction = bitcoin.splitTransactionBlockExplorer(transactionData);
                }
                else {
                    transaction = bitcoin.splitTransaction(transactionData);
                }
                return transaction;
            } 
            catch(e) {
                log.error(e);
                alert("Could not parse transaction");
                return;
            }     
        },
        
        updateWallet: function(privateKey, trustedInputKeyset, txs, unspent_outputs, progress) {
              // Parse the transaction
              var transaction;
              var redeemed = 0;
              var balance = 0;
              // Parse depending on the format (here only accept BBE)
              var txskeys = Object.keys(txs);
              for (var tr=0; tr<txskeys.length;tr++) {
                if (progress!=null) {
                  progress(tr/txskeys.length);
                }
                var tx = txs[txskeys[tr]];
                transaction = bitcoin.splitTransactionBlockExplorer(tx);
                if (typeof transaction == "undefined") {
                    return;
                }
                // Check redeemable outputs
                for (var i=0; i<transaction['outputs'].length; i++) {
                  
                        var currentOutput = transaction['outputs'][i];
                        var currentOutputScript = currentOutput['script'];
                        // If we have a private key matching, the output is redeemable          
                        if ((currentOutputScript.length == 0x19) && (currentOutputScript.bytes(0, 3).equals(BitcoinBasic.TRANSACTION_START)) &&
                                (currentOutputScript.bytes(0x17, 2).equals(BitcoinBasic.TRANSACTION_END))) {
                                var pubKeyHash = currentOutputScript.bytes(3, 0x14).toString(HEX);
                                //for (var index=0; index<privateKeys.length; index++) {
                                  
                                        // retrieve the key from the selected key
                                  
                                        // check the transaction match the 
                                        if (privateKey['hash160'] == pubKeyHash) {
                                          
                                            // only process the output as an trustedinput if it is unspent
                                            var unspent = false;
                                            for (var j=0; j<unspent_outputs.length;j++) {
                                              if (unspent_outputs[j]['tx_hash'] == transaction['hash'] 
                                                  && unspent_outputs[j]['tx_output_n'] == i ) {
                                                unspent = true;
                                                break;
                                              }
                                            }
                                            if (! unspent) {
                                              // remove it from the existing wallet too
                                              for (var j = 0; j < wallet.length; j++) {
                                                if (wallet[j]['tx_hash'] == transaction['hash'] 
                                                  && wallet[j]['tx_out_n'] == i) {
                                                  delete wallet[j];
                                                  break;
                                                }
                                              }
                                            }
                                            else {
                                          
                                                // avoid rehashing the trusted input (DAMN SLOW) check the wallet
                                                var foundInWallet = false;
                                                for (var j = 0; j < wallet.length; j++) {
                                                  if (wallet[j]['tx_hash'] == transaction['hash'] 
                                                    && wallet[j]['tx_out_n'] == i) {
                                                    foundInWallet = true;
                                                    break;
                                                  }
                                                }
                                                if (! foundInWallet) {
                                                    // Compute the trusted input 
                                                    // TODO : hash the transaction first, in case it is already present
                                                    
                                                    var trustedInput = bitcoin.getTrustedInput(trustedInputKeyset, i, transaction);
                                                    var currentHash = trustedInput.bytes(4, 32);
                                                    var currentIndex = trustedInput.bytes(4 + 32, 4);
                                                    var currentAmount = trustedInput.bytes(4 + 32 + 4, 8);
                                                    var trustedInputShared = trustedInput.bytes(4, 36).toString(HEX);

                                                    /*
                                                    var alreadyPresent = false;
                                                    // Merge if not included in wallet
                                                    for (var j=0; j<wallet.length; j++) {
                                                            if (wallet[j]['trustedInput'].substring(8, (40 * 2)) == trustedInputShared) {
                                                                    alreadyPresent = true;
                                                                    break;
                                                            }
                                                    }
                                                    if (!alreadyPresent) {
                                                    */
                                                            var currentAmountArray = [];
                                                            for (var j=0; j<currentAmount.length; j++) {
                                                                    currentAmountArray.push(currentAmount.byteAt(currentAmount.length - j - 1));
                                                            }
                                                            var currentAmountNumber = Bitcoin.Util.formatValue(currentAmountArray);
                                                            var currentItem = {};
                                                            currentItem['tx_hash'] = transaction['hash'];
                                                            currentItem['tx_out_n'] = i;
                                                            currentItem['trustedInput'] = trustedInput.toString(HEX);
                                                            currentItem['outputScript'] = currentOutputScript.toString(HEX);
                                                            currentItem['amount'] = currentAmountNumber;
                                                            balance += currentAmountNumber;
                                                            currentItem['kek'] = trustedInputKeyset;
                                                            wallet.push(currentItem);
                                                            redeemed++;
                                                    //}
                                                }
                                            }
                                        }
                                //}
                        }
                }
              }
              /*
              if (redeemed != 0) {
                              $("#wallet").html(JSON.stringify(wallet));
                              refreshWallet();                                        
              }
              */
              log.debug("Redeemed outputs : " + redeemed + " Balance: " + balance);
        }

});

BitcoinBasic.SECP256K1_COMPONENTS = new ByteString("20000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000720fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b820fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020001", HEX);

BitcoinBasic.KEY_ROLE_BITCOIN_PRIVATE_KEY_ENCRYPTION = 0x20;
BitcoinBasic.KEY_ROLE_BITCOIN_SECURE_HASH_ENCRYPTION = 0x21;
BitcoinBasic.KEY_ROLE_BITCOIN_AUTHORIZED_ADDRESS_ENCRYPTION = 0x22;
BitcoinBasic.KEY_ROLE_BITCOIN_TRUSTED_INPUT_ENCRYPTION = 0x23;
BitcoinBasic.KEY_ROLE_BITCOIN_TRANSACTION_AUTHORIZATION_SIGNATURE = 0x24;
BitcoinBasic.KEY_ROLE_BITCOIN_TRUSTED_SECURE_CHANNEL = 0x25;
BitcoinBasic.KEY_ROLE_BITCOIN_PRIVATE_KEY_SIGNATURE = 0x26;
BitcoinBasic.KEY_ROLE_BITCOIN_MODE_SIGNATURE = 0x27;
BitcoinBasic.KEY_ROLE_BITCOIN_PRIVATE_KEY_DIVERSIFICATION = 0x28;

BitcoinBasic.KEY_FLAG_TRUSTED_ONLY = 0x01;
BitcoinBasic.KEY_FLAG_SELF_CHANGE = 0x02;

BitcoinBasic.KEY_PREPARE_FLAG_BASE58_ENCODED = 0x02;
BitcoinBasic.KEY_PREPARE_FLAG_HASH_SHA256 = 0x04;
BitcoinBasic.KEY_PREPARE_DERIVE = 0x08;

BitcoinBasic.SIGHASH_ALL = 1;

BitcoinBasic.DEFAULT_LOCKTIME = new ByteString("00000000", HEX);

BitcoinBasic.OPERATION_MODE_TRUSTED = 0x01;
BitcoinBasic.OPERATION_MODE_MODERATELY_TRUSTED = 0x02;
BitcoinBasic.OPERATION_MODE_UNTRUSTED = 0x04;
BitcoinBasic.OPERATION_MODE_UNTRUSTED_NOSIGN = 0x08;

BitcoinBasic.TRANSACTION_START = new ByteString("76a914", HEX);
BitcoinBasic.TRANSACTION_END = new ByteString("88ac", HEX);
