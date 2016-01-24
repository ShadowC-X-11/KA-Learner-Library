var KA_LL = {
	rot13: function(inputString) {
	// ROT-13 by Ben Alpert
	// See: http://stackoverflow.com/questions/617647/where-is-my-one-line-implementation-of-rot13-in-javascript-going-wrong
	return inputString.replace(/[a-zA-Z]/g,
	function(c){
		return String.fromCharCode((c<="Z"?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26);}) 
	},
	onKA: (document.location.origin === "https://www.kasandbox.org"),
	storage: {
		// A function that stores data in sessionStorage
		// if program is running in KA sandbox, uses localStorage
		// otherwise.
		// May be updated with techniques that mimic localStorage on KA
		// allowing programs extra functionality without modification.
		get: function(key, value) {
			if (KA_LL.onKA) {
				return sessionStorage.getItem(key, value);
			} else {
				return localStorage.getItem(key, value);
			}},
		set: function(key, value) {
			if (KA_LL.onKA) {
				sessionStorage.setItem(key, value);
			} else {
				localStorage.setItem(key, value);
			}},
		clear: function() {
			if (KA_LL.onKA) {
				sessionStorage.clear();
			} else {
				localStorage.clear();
			}},
		remove: function(key, value) {
			if (KA_LL.onKA) {
				sessionStorage.removeItem(key, value);
			} else {
				localStorage.removeItem(key, value);
			}
		}},
	randomChoice: function(choices) {
		/**
		* Ever wanted to choose randomly between several options?
		* Tried doing so with the random(min, max) function?
		* That didn't work out for you, did it?
		* That's because random(min, max) only works with numbers and
		* gives ANYTHING in between. Even fractions.
		* 
		* Well! Now there's the randomChoice(choices) function!
		* @author Dalendrion
		* @param {...Mixed} choices - Any number of any type of value you could ever want!
		* @returns {Mixed} Returns one of the given arguments at random.
		*			each argument has an equal chance of being returned.
		*/
		return arguments[floor(random(arguments.length))];
	},
	randomizeChildren: function(tagName) {
		// randomizes the children of element type provided
		// snagged from @pamela's contest result programs, modified
		var lists = document.getElementsByTagName(tagName);
		for (var j = 0; j < lists.length; j++) {
			var theList = lists[j];
			for (var i = theList.children.length; i >= 0; i--) {
				theList.appendChild(theList.children[Math.random() * i | 0]);
			}
		}
	},
	objSort: function(key, ordering) {
		// returns a function to be passed to Array.sort()
		// that sorts an array of objects by a given key
		// pass -1 as second param for reverse order
		ordering = ordering || 1;
		var theFunction = function(a, b) {
			if (a[key] < b[key]) {
				return -1 * ordering;
			} else if (a[key] === b[key]) {
				return 0;
			} else {
				return 1 * ordering;
			}
		};
		return theFunction;
	},
	modinv: function(a, n){
		// Taken from https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Code
		// Calculates the modular multiplicative inverse
		// Added for the RSA functions
    	var t  = 0,
            nt = 1,
            r  = n,
            nr = a % n;
        if (n < 0){
        	n = -n;
        }
        if (a < 0){
        	a = n - (-a % n);
        }
    	while (nr !== 0) {
    		var quot= (r/nr) | 0;
    		var tmp = nt;  nt = t - quot*nt;  t = tmp;
    		    tmp = nr;  nr = r - quot*nr;  r = tmp;
    	}
    	if (r > 1) { return -1; }
    	if (t < 0) { t += n; }
    	return t;
    },
	isPrime: function(number){
		// Checks if a number is prime
		for(var i = 0; i <= floor(Math.sqrt(number)); i++){
			if(number % i === 0){
				return false;
			}
		}
		return true;
	},
	randomPrime: function(min, max){
		// generates a random prime number
		while(true){
			var rnd = Math.floor(Math.random() * ((max - 1) - min + 1)) + min;
			var s = Math.floor(Math.sqrt(rnd));
			for(var i = 2; i <= s; i++){
				if(rnd % i === 0){
					continue;
				}
			}
			return rnd;
		}
	},
	gcd: function(num1, num2){
		// Calculates the Greatest Common Denominator
		var b = num1 > num2 ? num2 : num1;
		var gcd = 0;
		for(var i = 1; i <= b; i++){
			if(num1 % i === 0 && num2 % i === 0){
				gcd = i;
			}
		}
		return gcd;
	},
	rsaEncrypt: function(text, ek){
		// Generates RSA encrypted data
		var returned = {};
		if(typeof ek !== "string"){
			var p = KA_LL.randomPrime(1, 1000);
			var q = KA_LL.randomPrime(1, 1000);
			var m = p * q;
			var phim = m - (p + q - 1);
			var en = m - 1;
			while(KA_LL.gcd(en, m) !== 1){
				var en = KA_LL.randomPrime(1, phim);
			}
			var dn = KA_LL.modinv(en, phim);
			returned.privKey = dn.toString() + "," + m.toString();
			ek = returned.publKey = en.toString() + "," + m.toString();
		}
		var data = ek.split(",");
		var ek = parseInt(data[0]);
		var m = parseInt(data[1]);
		var encMess = "";
		var allowed = "a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 A B C D E F G H I J K L M N O P Q R S T U V W X Y Z \\! \\? \\. , @ # \\$ % & \\:\\/ \\\\ \\< \\> \\[ \\] \\{ \\} ~ \\^ \\( \\) \\- \\_ \\=".split(" ");
		allowed.push(" ");
		for(var i = 0; i < text.length; i++){
			if(i !== 0) encMess += ", ";
			var tmp = allowed.indexOf(text[i]);
			alert(tmp);
			if(tmp === -1){
				tmp = allowed.indexOf("?");
			}
			tmp = Math.pow(tmp, ek) % m;
			encMess += tmp;
		}
		returned.encrptdMsg = encMess;
		return returned;
	},
	rsaDecrypt: function(encMsg, pk){
		// decrypts RSA encrypted data
		if(typeof pk !== "string"){
			return null;
		}
		var data = pk.split(",");
		var dk = parseInt(data[0]);
		var m = parseInt(data[1]);
		var alphalist = "a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 A B C D E F G H I J K L M N O P Q R S T U V W X Y Z \\! \\? \\. , @ # \\$ % & \\:\\/ \\\\ \\< \\> \\[ \\] \\{ \\} ~ \\^ \\( \\) \\- \\_ \\=".split(" ");
		alphalist.push(" ");
		var msgvals = encMsg.split(" ");
		var out = "";
		for(var i = 0; i < msgvals.length; i++){
			out += alphalist[Math.pow(parseInt(msgvals[i]), dk) % m];
		}
		return out;
	}
};

