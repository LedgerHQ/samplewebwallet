var SecureChannelCard = Class.extend(Card, {
	/** @lends SecureChannelCard.prototype */
	
	/**
	 *  @class Card interface offered by a Secure Channel
	 *  @param {Card} card card associated to this Secure Channel
	 *  @param {SecureChannel} secureChannel Secure Channel
	 *  @constructs
	 *  @augments Card
	 */	
	initialize: function(card, secureChannel) {
		if (!(card instanceof Card)) {
			throw "Invalid card";
		}
		/*
		if (!(secureChannel instanceof SecureChannel)) {
			throw "Invalid Secure Channel";
		}
		*/
		this.card = card;
		this.secureChannel = secureChannel;
	},
	
	/**
	 * Set the keyset keys values associated to this Secure Channel
	 * @param {Array|ByteString} keys array of ByteString keys values for ENC/MAC/DEK keys or unique ByteString for a shared base key 
	 */
	setKeyset : function(keys) {
		this.keys = keys;
	},
	
	/**
	 * Set the diversification algorithm to use. RFU.
	 * @param {String} diversificationAlgorithm diversification algorithm
	 */
	setDiversificationAlgorithm : function(diversificationAlgorithm) {
		this.diversificationAlgorithm = diversificationAlgorithm;
	},
	
	/**
	 * Open the Secure Channel session 
	 * @param {Number} Security Level of the Secure Channel. Bitmask of SecureChannel.SCP_SECURITY_LEVEL_ options
	 * @param {Number} keyVersion version of the target keyset to use 
	 */
	openSession: function(securityLevel, keyVersion) {
		var result;
		this.close();
		var initializeUpdateResponse;
		var externalAuthenticateAPDU;
		try {
			result = this.secureChannel.openSession(0x15, securityLevel, keyVersion);
		}
		catch(e) {			
			throw "Failed to generate INITIALIZE UPDATE " + e;
		}
		this.sessionId = result['sessionID'];
		try {
			initializeUpdateResponse = this.card.exchange(result['data'], [0x9000]);
		}
		catch(e) {
			throw "Failed to process INITIALIZE UPDATE " + e;
		}
		try {
			externalAuthenticateAPDU = this.secureChannel.getExternalAuthenticateAPDU(this.sessionId, this.keys, initializeUpdateResponse, this.diversificationAlgorithm);
		}
		catch(e) {
			throw "Failed to generate EXTERNAL AUTHENTICATE " + e;
		}
		try {
			this.card.exchange(externalAuthenticateAPDU, [0x9000]);
		}
		catch(e) {
			throw "Failed to exchange EXTERNAL AUTHENTICATE " + e;
		}
		this.opened = true;
	},
	
	sendApdu : function(cla, ins, p1, p2, opt1, opt2, opt3) {
		return this.card.sendApdu(cla, ins, p1, p2, opt1, opt2, opt3, 
			   this);
	},	
		
	exchangeWrapped : function(apdu, returnLength) {
		if (!(apdu instanceof ByteString)) {
			throw "Invalid APDU";
		}
		try {
			if (!this.opened) {
				throw "Invalid state";
			}
			else {
				// Normalize the APDU length before wrapping it if dealing with a Case 2
				if ((apdu.byteAt(4) != 0x00) && (apdu.length == 5)) {
					apdu = apdu.bytes(0, 4);
					apdu = apdu.concat(new ByteString("00", HEX));
					
				}
				var wrapped = this.secureChannel.wrapAPDU(this.sessionId, apdu);
				var response = this.card.exchange(wrapped, returnLength);
				this.SW = this.card.SW;
				this.SW1 = this.card.SW1;
				this.SW2 = this.card.SW2;
				// append SW to data
				var swString = Convert.toHexByte(this.card.getSW1()) + Convert.toHexByte(this.card.getSW2());
				response = response.concat(new ByteString(swString, HEX));
				return this.secureChannel.unwrapAPDU(this.sessionId, response);
			}
		}
		catch (e) {
			throw e;
			throw "Error wrapping APDU";
		}
	},

        getPutKeyAPDU: function(keyIds, originalKeyVersion, newKeyVersion, initializeUpdateResponse, diversificationAlgorithm, keyUsage, keyAccess, keyDiversifier, diversifier1, diversifier2) {
                return this.secureChannel.getPutKeyAPDU(this.sessionId, keyIds, originalKeyVersion, newKeyVersion, initializeUpdateResponse, diversificationAlgorithm, keyUsage, keyAccess, keyDiversifier, diversifier1, diversifier2, true);
        },

	/**
	 * Close this Secure Channel
	 */
	close : function() {
		this.opened = false;
		if (typeof this.sessionId != "undefined") {
			this.secureChannel.closeSession(this.sessionId);
			this.sessionId = undefined;
		}
	}
	
	
});
