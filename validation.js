/**
 * MetasBank — International Input Validation Library
 * Covers: IBAN, SWIFT/BIC, Sort Code, US Routing, Phone, Card (Luhn), SSN/EIN, Postal, Crypto
 */

const MetasValidate = (() => {

  // ===== PHONE NUMBER VALIDATION (Europe-focused) =====
  const PHONE_RULES = {
    'GB': { pattern: /^(\+44|0044|0)\s?[1-9]\d{8,9}$/, label: 'UK', example: '+44 7911 123456' },
    'DE': { pattern: /^(\+49|0049|0)\s?[1-9]\d{6,14}$/, label: 'Germany', example: '+49 151 12345678' },
    'FR': { pattern: /^(\+33|0033|0)\s?[1-9]\d{8}$/, label: 'France', example: '+33 6 12 34 56 78' },
    'ES': { pattern: /^(\+34|0034)\s?[6-9]\d{8}$/, label: 'Spain', example: '+34 612 345 678' },
    'IT': { pattern: /^(\+39|0039)\s?[3]\d{8,9}$/, label: 'Italy', example: '+39 312 345 6789' },
    'NL': { pattern: /^(\+31|0031)\s?[1-9]\d{8}$/, label: 'Netherlands', example: '+31 6 12345678' },
    'BE': { pattern: /^(\+32|0032)\s?[1-9]\d{7,8}$/, label: 'Belgium', example: '+32 470 12 34 56' },
    'CH': { pattern: /^(\+41|0041)\s?[1-9]\d{8}$/, label: 'Switzerland', example: '+41 76 123 45 67' },
    'AT': { pattern: /^(\+43|0043)\s?[1-9]\d{6,12}$/, label: 'Austria', example: '+43 664 1234567' },
    'PT': { pattern: /^(\+351|00351)\s?[1-9]\d{8}$/, label: 'Portugal', example: '+351 912 345 678' },
    'IE': { pattern: /^(\+353|00353)\s?[1-9]\d{7,8}$/, label: 'Ireland', example: '+353 86 123 4567' },
    'PL': { pattern: /^(\+48|0048)\s?[1-9]\d{8}$/, label: 'Poland', example: '+48 501 234 567' },
    'SE': { pattern: /^(\+46|0046)\s?[1-9]\d{7,9}$/, label: 'Sweden', example: '+46 70 123 45 67' },
    'NO': { pattern: /^(\+47|0047)\s?[1-9]\d{7}$/, label: 'Norway', example: '+47 412 34 567' },
    'DK': { pattern: /^(\+45|0045)\s?[1-9]\d{7}$/, label: 'Denmark', example: '+45 20 12 34 56' },
    'FI': { pattern: /^(\+358|00358)\s?[1-9]\d{7,9}$/, label: 'Finland', example: '+358 40 123 4567' },
    'CZ': { pattern: /^(\+420|00420)\s?[1-9]\d{8}$/, label: 'Czech Republic', example: '+420 601 123 456' },
    'RO': { pattern: /^(\+40|0040)\s?[1-9]\d{8}$/, label: 'Romania', example: '+40 712 345 678' },
    'HU': { pattern: /^(\+36|0036)\s?[1-9]\d{7,8}$/, label: 'Hungary', example: '+36 30 123 4567' },
    'GR': { pattern: /^(\+30|0030)\s?[1-9]\d{9}$/, label: 'Greece', example: '+30 697 123 4567' },
    'US': { pattern: /^(\+1|001)\s?[2-9]\d{2}\s?[2-9]\d{6}$/, label: 'USA', example: '+1 202 555 0123' },
    'CA': { pattern: /^(\+1|001)\s?[2-9]\d{2}\s?[2-9]\d{6}$/, label: 'Canada', example: '+1 416 555 0123' },
    'AU': { pattern: /^(\+61|0061)\s?[2-9]\d{8,9}$/, label: 'Australia', example: '+61 412 345 678' },
    'NG': { pattern: /^(\+234|00234|0)\s?[789]\d{9}$/, label: 'Nigeria', example: '+234 802 123 4567' },
    'ZA': { pattern: /^(\+27|0027)\s?[1-9]\d{8}$/, label: 'South Africa', example: '+27 82 123 4567' },
    'JP': { pattern: /^(\+81|0081)\s?[1-9]\d{8,9}$/, label: 'Japan', example: '+81 90 1234 5678' },
    'BR': { pattern: /^(\+55|0055)\s?[1-9]{2}\s?[9]?\d{8}$/, label: 'Brazil', example: '+55 11 91234 5678' },
    'HR': { pattern: /^(\+385|00385)\s?[1-9]\d{7,8}$/, label: 'Croatia', example: '+385 91 234 5678' },
    'SI': { pattern: /^(\+386|00386)\s?[1-9]\d{6,7}$/, label: 'Slovenia', example: '+386 41 234 567' },
    'RS': { pattern: /^(\+381|00381)\s?[1-9]\d{6,8}$/, label: 'Serbia', example: '+381 61 234 5678' },
    'ME': { pattern: /^(\+382|00382)\s?[1-9]\d{7}$/, label: 'Montenegro', example: '+382 67 234 567' },
    'MK': { pattern: /^(\+389|00389)\s?[1-9]\d{7}$/, label: 'North Macedonia', example: '+389 70 234 567' },
    'AL': { pattern: /^(\+355|00355)\s?[1-9]\d{7,8}$/, label: 'Albania', example: '+355 69 234 5678' },
    'BG': { pattern: /^(\+359|00359)\s?[1-9]\d{7,8}$/, label: 'Bulgaria', example: '+359 87 234 5678' },
    'LT': { pattern: /^(\+370|00370)\s?[1-9]\d{7}$/, label: 'Lithuania', example: '+370 612 34567' },
    'LV': { pattern: /^(\+371|00371)\s?[1-9]\d{7}$/, label: 'Latvia', example: '+371 21 234 567' },
    'EE': { pattern: /^(\+372|00372)\s?[1-9]\d{6,7}$/, label: 'Estonia', example: '+372 5123 4567' },
    'UA': { pattern: /^(\+380|00380)\s?[1-9]\d{8}$/, label: 'Ukraine', example: '+380 67 123 4567' },
    'NZ': { pattern: /^(\+64|0064)\s?[2-9]\d{7,8}$/, label: 'New Zealand', example: '+64 21 234 5678' },
    'KR': { pattern: /^(\+82|0082)\s?[1-9]\d{8,9}$/, label: 'South Korea', example: '+82 10 1234 5678' },
    'CN': { pattern: /^(\+86|0086)\s?1[3-9]\d{9}$/, label: 'China', example: '+86 138 1234 5678' },
    'IN': { pattern: /^(\+91|0091)\s?[6-9]\d{9}$/, label: 'India', example: '+91 98765 43210' },
    'MX': { pattern: /^(\+52|0052)\s?[1-9]\d{9}$/, label: 'Mexico', example: '+52 55 1234 5678' },
    'EG': { pattern: /^(\+20|0020)\s?[1][0-9]{9}$/, label: 'Egypt', example: '+20 100 123 4567' },
    'IL': { pattern: /^(\+972|00972)\s?[5-9]\d{8}$/, label: 'Israel', example: '+972 50 123 4567' },
    'AE': { pattern: /^(\+971|00971)\s?[5-9]\d{8}$/, label: 'UAE', example: '+971 50 123 4567' },
    'SA': { pattern: /^(\+966|00966)\s?[5-9]\d{8}$/, label: 'Saudi Arabia', example: '+966 50 123 4567' },
    'TR': { pattern: /^(\+90|0090)\s?[5-9]\d{9}$/, label: 'Turkey', example: '+90 532 123 4567' },
    'PK': { pattern: /^(\+92|0092)\s?[3-9]\d{9}$/, label: 'Pakistan', example: '+92 300 123 4567' },
    'PH': { pattern: /^(\+63|0063)\s?[9]\d{9}$/, label: 'Philippines', example: '+63 917 123 4567' },
    'MY': { pattern: /^(\+60|0060)\s?[1-9]\d{8,9}$/, label: 'Malaysia', example: '+60 12 345 6789' },
    'SG': { pattern: /^(\+65|0065)\s?[6-9]\d{7}$/, label: 'Singapore', example: '+65 9123 4567' },
    'TH': { pattern: /^(\+66|0066)\s?[1-9]\d{8}$/, label: 'Thailand', example: '+66 81 234 5678' },
    'VN': { pattern: /^(\+84|0084)\s?[1-9]\d{8,9}$/, label: 'Vietnam', example: '+84 91 234 5678' },
    'ID': { pattern: /^(\+62|0062)\s?[1-9]\d{8,10}$/, label: 'Indonesia', example: '+62 812 3456 7890' },
  };

  function validatePhone(value, countryCode) {
    if (!value || !value.trim()) return { valid: false, error: 'Phone number is required' };
    let v = value.replace(/[\s\-\(\)\.]/g, '').trim();
    let country = countryCode || 'GB';
    // Strip leading 0 if country code prefix is present
    let rules = PHONE_RULES[country];
    if (!rules) {
      // Generic check: must start with + and have 7-15 digits
      if (/^\+\d{7,15}$/.test(v)) return { valid: true };
      return { valid: false, error: 'Phone must start with + and country code (e.g. +44, +49)' };
    }
    if (!rules.pattern.test(v)) {
      return { valid: false, error: `Invalid ${rules.label} phone. Example: ${rules.example}` };
    }
    let digits = v.replace(/\D/g, '');
    if (digits.length < 8 || digits.length > 15) {
      return { valid: false, error: `Phone number must be 8-15 digits` };
    }
    return { valid: true };
  }

  // ===== CARD NUMBER — LUHN ALGORITHM =====
  function luhnCheck(num) {
    let arr = num.split('').reverse().map(Number);
    let sum = 0;
    for (let i = 0; i < arr.length; i++) {
      let d = arr[i];
      if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    return sum % 10 === 0;
  }

  function detectCardBrand(number) {
    let n = number.replace(/\D/g, '');
    if (/^4[0-9]{12}(?:[0-9]{3})?$/.test(n)) return 'visa';
    if (/^5[1-5][0-9]{14}$/.test(n) || /^2(?:2[2-9][1-9]|[3-6][0-9][0-9]|7[01][0-9]|720)[0-9]{12}$/.test(n)) return 'mastercard';
    if (/^3[47][0-9]{13}$/.test(n)) return 'amex';
    if (/^6(?:011|5[0-9]{2}|4[4-9][0-9]{2})[0-9]{12,15}$/.test(n)) return 'discover';
    return 'unknown';
  }

  function validateCardNumber(value) {
    if (!value) return { valid: false, error: 'Card number is required' };
    let n = value.replace(/\D/g, '');
    let brand = detectCardBrand(n);
    let lenRanges = { visa: [13,16], mastercard: [16,16], amex: [15,15], discover: [16,19] };
    let range = lenRanges[brand] || [16,16];
    if (n.length < range[0] || n.length > range[1]) {
      return { valid: false, error: `${brand.charAt(0).toUpperCase() + brand.slice(1)} requires ${range[0]}-${range[1]} digits. You entered ${n.length}.` };
    }
    if (!luhnCheck(n)) {
      return { valid: false, error: 'Invalid card number (failed checksum)' };
    }
    return { valid: true, brand };
  }

  function validateCVC(value, brand) {
    if (!value) return { valid: false, error: 'CVC is required' };
    let v = value.replace(/\D/g, '');
    let expected = brand === 'amex' ? 4 : 3;
    if (v.length !== expected) {
      return { valid: false, error: `CVC must be ${expected} digits` };
    }
    return { valid: true };
  }

  function validateCardExpiry(value) {
    if (!value) return { valid: false, error: 'Expiry date is required' };
    let match = value.match(/^(\d{2})\s?\/\s?(\d{2})$/);
    if (!match) return { valid: false, error: 'Format: MM / YY' };
    let month = parseInt(match[1], 10);
    let year = parseInt('20' + match[2], 10);
    if (month < 1 || month > 12) return { valid: false, error: 'Invalid month' };
    let now = new Date();
    let expDate = new Date(year, month, 0); // last day of month
    if (expDate < now) return { valid: false, error: 'Card is expired' };
    return { valid: true };
  }

  // ===== IBAN VALIDATION =====
  const IBAN_LENGTHS = {
    'AL': 28, 'AD': 24, 'AT': 20, 'AZ': 28, 'BH': 22, 'BY': 28, 'BE': 16,
    'BA': 20, 'BR': 29, 'BG': 22, 'CR': 22, 'HR': 21, 'CY': 28, 'CZ': 24,
    'DK': 18, 'DO': 28, 'TL': 23, 'EE': 20, 'FO': 18, 'FI': 18, 'FR': 27,
    'GE': 22, 'DE': 22, 'GI': 23, 'GR': 27, 'GL': 18, 'GT': 28, 'HU': 28,
    'IS': 26, 'IQ': 23, 'IE': 22, 'IL': 23, 'IT': 27, 'JO': 30, 'KZ': 20,
    'XK': 20, 'KW': 30, 'LV': 21, 'LB': 28, 'LI': 21, 'LT': 20, 'LU': 20,
    'MK': 19, 'MT': 31, 'MR': 27, 'MU': 30, 'MC': 27, 'MD': 24, 'ME': 22,
    'NL': 18, 'NO': 15, 'PK': 24, 'PS': 29, 'PL': 28, 'PT': 25, 'QA': 29,
    'RO': 24, 'LC': 32, 'SM': 27, 'ST': 25, 'SA': 24, 'RS': 22, 'SC': 31,
    'SK': 24, 'SI': 19, 'ES': 24, 'SE': 24, 'CH': 21, 'TN': 24, 'TR': 26,
    'UA': 29, 'AE': 23, 'GB': 22, 'VA': 22, 'VG': 24
  };

  function validateIBAN(value) {
    if (!value) return { valid: false, error: 'IBAN is required' };
    let v = value.replace(/\s/g, '').toUpperCase();
    let cc = v.substring(0, 2);
    if (!/^[A-Z]{2}/.test(cc)) return { valid: false, error: 'IBAN must start with 2-letter country code (e.g. DE, GB, FR)' };
    let expectedLen = IBAN_LENGTHS[cc];
    if (!expectedLen) return { valid: false, error: `Unknown country code: ${cc}` };
    if (v.length !== expectedLen) return { valid: false, error: `${cc} IBAN must be ${expectedLen} characters. You entered ${v.length}.` };
    if (!/^[A-Z0-9]+$/.test(v)) return { valid: false, error: 'IBAN contains invalid characters' };
    // MOD-97 check (ISO 7064)
    let rearranged = v.substring(4) + v.substring(0, 4);
    let numeric = rearranged.replace(/[A-Z]/g, c => (c.charCodeAt(0) - 55).toString());
    let remainder = numeric;
    while (remainder.length > 2) {
      let block = remainder.substring(0, 9);
      remainder = (parseInt(block, 10) % 97).toString() + remainder.substring(block.length);
    }
    if (parseInt(remainder, 10) % 97 !== 1) return { valid: false, error: 'IBAN checksum failed — invalid IBAN' };
    return { valid: true, country: cc };
  }

  // ===== SWIFT / BIC CODE =====
  function validateSWIFT(value) {
    if (!value) return { valid: false, error: 'SWIFT code is required' };
    let v = value.replace(/\s/g, '').toUpperCase();
    if (v.length !== 8 && v.length !== 11) return { valid: false, error: 'SWIFT/BIC must be 8 or 11 characters' };
    if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(v)) {
      return { valid: false, error: 'Invalid SWIFT format. Format: AAAA CC XX (e.g. DEUTDEFF)' };
    }
    return { valid: true };
  }

  // ===== SORT CODE (UK) =====
  function validateSortCode(value) {
    if (!value) return { valid: false, error: 'Sort code is required' };
    let v = value.replace(/[\s\-]/g, '');
    if (!/^\d{6}$/.test(v)) return { valid: false, error: 'UK sort code must be 6 digits (e.g. 12-34-56)' };
    return { valid: true };
  }

  // ===== US ROUTING NUMBER (ABA) =====
  function validateUSRouting(value) {
    if (!value) return { valid: false, error: 'Routing number is required' };
    let v = value.replace(/\D/g, '');
    if (v.length !== 9) return { valid: false, error: 'US routing number must be exactly 9 digits' };
    // ABA checksum
    let d = v.split('').map(Number);
    let checksum = (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10;
    if (checksum !== 0) return { valid: false, error: 'Invalid routing number (checksum failed)' };
    return { valid: true };
  }

  // ===== US SSN =====
  function validateSSN(value) {
    if (!value) return { valid: false, error: 'SSN is required' };
    let v = value.replace(/[\s\-]/g, '');
    if (!/^\d{9}$/.test(v)) return { valid: false, error: 'SSN must be 9 digits (e.g. 123-45-6789)' };
    let area = parseInt(v.substring(0, 3), 10);
    let group = parseInt(v.substring(3, 5), 10);
    let serial = parseInt(v.substring(5, 9), 10);
    if (area === 0) return { valid: false, error: 'SSN area number cannot be 000' };
    if (area === 666) return { valid: false, error: 'SSN area number cannot be 666' };
    if (area >= 900) return { valid: false, error: 'SSN area number cannot be 900 or above' };
    if (group === 0) return { valid: false, error: 'SSN group number cannot be 00' };
    if (serial === 0) return { valid: false, error: 'SSN serial number cannot be 0000' };
    if (v === '123456789') return { valid: false, error: 'Invalid SSN' };
    return { valid: true, formatted: v.substring(0,3) + '-' + v.substring(3,5) + '-' + v.substring(5,9) };
  }

  // ===== US TAX ID / EIN =====
  function validateEIN(value) {
    if (!value) return { valid: false, error: 'Tax ID / EIN is required' };
    let v = value.replace(/[\s\-]/g, '');
    if (!/^\d{9}$/.test(v)) return { valid: false, error: 'Tax ID must be 9 digits (e.g. 12-3456789)' };
    let validPrefixes = ['10','11','12','13','14','16','20','21','22','23','24','25','30','31','32','33','34','35','36','37','38','39','40','41','42','43','44','45','46','47','48','50','51','52','53','54','55','56','57','58','59','60','61','62','63','64','65','66','67','68','71','72','73','74','75','76','77','78','80','81','82','83','84','85','86','87','88','90','91','92','93','94','95','98','99'];
    let prefix = v.substring(0, 2);
    if (!validPrefixes.includes(prefix)) return { valid: false, error: 'Invalid Tax ID prefix' };
    return { valid: true, formatted: v.substring(0,2) + '-' + v.substring(2,9) };
  }

  // ===== POSTAL CODE BY COUNTRY =====
  const POSTAL_RULES = {
    'US': { pattern: /^\d{5}(-\d{4})?$/, label: 'US ZIP', example: '10001 or 10001-1234' },
    'GB': { pattern: /^[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}$/i, label: 'UK postcode', example: 'SW1A 1AA' },
    'CA': { pattern: /^[A-Z]\d[A-Z]\s?\d[A-Z]\d$/i, label: 'Canadian postal code', example: 'K1A 0B1' },
    'DE': { pattern: /^\d{5}$/, label: 'German PLZ', example: '10115' },
    'FR': { pattern: /^\d{5}$/, label: 'French postal code', example: '75001' },
    'ES': { pattern: /^\d{5}$/, label: 'Spanish postal code', example: '28001' },
    'IT': { pattern: /^\d{5}$/, label: 'Italian CAP', example: '00100' },
    'NL': { pattern: /^\d{4}\s?[A-Z]{2}$/i, label: 'Dutch postal code', example: '1012 AB' },
    'BE': { pattern: /^\d{4}$/, label: 'Belgian postal code', example: '1000' },
    'CH': { pattern: /^\d{4}$/, label: 'Swiss postal code', example: '8001' },
    'AT': { pattern: /^\d{4}$/, label: 'Austrian postal code', example: '1010' },
    'PT': { pattern: /^\d{4}-?\d{3}$/, label: 'Portuguese postal code', example: '1000-001' },
    'IE': { pattern: /^[A-Z\d]{3}\s?[A-Z\d]{4}$/i, label: 'Irish Eircode', example: 'D02 AF30' },
    'PL': { pattern: /^\d{2}-?\d{3}$/, label: 'Polish postal code', example: '00-001' },
    'SE': { pattern: /^\d{3}\s?\d{2}$/, label: 'Swedish postal code', example: '111 22' },
    'NO': { pattern: /^\d{4}$/, label: 'Norwegian postal code', example: '0123' },
    'DK': { pattern: /^\d{4}$/, label: 'Danish postal code', example: '1000' },
    'FI': { pattern: /^\d{5}$/, label: 'Finnish postal code', example: '00100' },
    'CZ': { pattern: /^\d{3}\s?\d{2}$/, label: 'Czech postal code', example: '110 00' },
    'RO': { pattern: /^\d{6}$/, label: 'Romanian postal code', example: '010001' },
    'HU': { pattern: /^\d{4}$/, label: 'Hungarian postal code', example: '1011' },
    'GR': { pattern: /^\d{3}\s?\d{2}$/, label: 'Greek postal code', example: '104 31' },
    'JP': { pattern: /^\d{3}-?\d{4}$/, label: 'Japanese postal code', example: '100-0001' },
    'AU': { pattern: /^\d{4}$/, label: 'Australian postal code', example: '2000' },
    'BR': { pattern: /^\d{5}-?\d{3}$/, label: 'Brazilian CEP', example: '01001-000' },
    'NG': { pattern: /^\d{6}$/, label: 'Nigerian postal code', example: '100001' },
    'ZA': { pattern: /^\d{4}$/, label: 'South African postal code', example: '2000' },
    'HR': { pattern: /^\d{5}$/, label: 'Croatian postal code', example: '10000' },
    'SI': { pattern: /^\d{4}$/, label: 'Slovenian postal code', example: '1000' },
    'RS': { pattern: /^\d{5,6}$/, label: 'Serbian postal code', example: '11000' },
    'ME': { pattern: /^\d{5}$/, label: 'Montenegrin postal code', example: '81000' },
    'MK': { pattern: /^\d{4}$/, label: 'Macedonian postal code', example: '1000' },
    'AL': { pattern: /^\d{4}$/, label: 'Albanian postal code', example: '1000' },
    'BG': { pattern: /^\d{4}$/, label: 'Bulgarian postal code', example: '1000' },
    'LT': { pattern: /^\d{5}$/, label: 'Lithuanian postal code', example: '01001' },
    'LV': { pattern: /^LV-?\d{4}$/i, label: 'Latvian postal code', example: 'LV-1050' },
    'EE': { pattern: /^\d{5}$/, label: 'Estonian postal code', example: '10115' },
    'UA': { pattern: /^\d{5}$/, label: 'Ukrainian postal code', example: '01001' },
    'NZ': { pattern: /^\d{4}$/, label: 'New Zealand postal code', example: '6011' },
    'KR': { pattern: /^\d{5}$/, label: 'South Korean postal code', example: '03171' },
    'CN': { pattern: /^\d{6}$/, label: 'Chinese postal code', example: '100000' },
    'IN': { pattern: /^\d{6}$/, label: 'Indian PIN code', example: '110001' },
    'MX': { pattern: /^\d{5}$/, label: 'Mexican postal code', example: '06600' },
    'EG': { pattern: /^\d{5}$/, label: 'Egyptian postal code', example: '11511' },
    'IL': { pattern: /^\d{7}$/, label: 'Israeli postal code', example: '1234567' },
    'SA': { pattern: /^\d{5}$/, label: 'Saudi postal code', example: '11564' },
    'TR': { pattern: /^\d{5}$/, label: 'Turkish postal code', example: '06000' },
    'PK': { pattern: /^\d{5}$/, label: 'Pakistani postal code', example: '54000' },
    'PH': { pattern: /^\d{4}$/, label: 'Philippine postal code', example: '1000' },
    'MY': { pattern: /^\d{5}$/, label: 'Malaysian postal code', example: '50000' },
    'SG': { pattern: /^\d{6}$/, label: 'Singapore postal code', example: '018956' },
    'TH': { pattern: /^\d{5}$/, label: 'Thai postal code', example: '10110' },
    'VN': { pattern: /^\d{6}$/, label: 'Vietnamese postal code', example: '100000' },
    'ID': { pattern: /^\d{5}$/, label: 'Indonesian postal code', example: '10110' },
  };

  function validatePostalCode(value, countryCode) {
    if (!value) return { valid: false, error: 'Postal code is required' };
    let country = countryCode || 'GB';
    let rules = POSTAL_RULES[country];
    if (!rules) {
      // Generic: alphanumeric, 3-10 chars
      if (/^[A-Z0-9\s\-]{3,10}$/i.test(value.trim())) return { valid: true };
      return { valid: false, error: 'Invalid postal code format' };
    }
    if (!rules.pattern.test(value.trim())) {
      return { valid: false, error: `Invalid ${rules.label}. Example: ${rules.example}` };
    }
    return { valid: true };
  }

  // ===== CRYPTO WALLET ADDRESS =====
  function validateCryptoAddress(value, coin) {
    if (!value) return { valid: false, error: 'Wallet address is required' };
    let v = value.trim();
    let patterns = {
      'BTC': /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/,
      'ETH': /^0x[a-fA-F0-9]{40}$/,
      'LTC': /^(ltc1|[LM])[a-zA-HJ-NP-Z0-9]{26,62}$/,
      'USDT': /^0x[a-fA-F0-9]{40}$/,
      'USDC': /^0x[a-fA-F0-9]{40}$/,
      'XRP': /^r[a-zA-HJ-NP-Z0-9]{24,34}$/,
      'DOGE': /^(D|A)[a-zA-HJ-NP-Z0-9]{33,34}$/,
      'SOL': /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
    };
    let pattern = patterns[coin] || /^0x[a-fA-F0-9]{40}$/;
    if (!pattern.test(v)) {
      return { valid: false, error: `Invalid ${coin || 'crypto'} wallet address format` };
    }
    return { valid: true };
  }

  // ===== ACCOUNT NUMBER (generic) =====
  function validateAccountNumber(value, method) {
    if (!value) return { valid: false, error: 'Account number is required' };
    let v = value.replace(/\D/g, '');
    if (v.length < 4) return { valid: false, error: 'Account number must be at least 4 digits' };
    if (v.length > 17) return { valid: false, error: 'Account number cannot exceed 17 digits' };
    return { valid: true };
  }

  // ===== EMAIL =====
  function validateEmail(value) {
    if (!value) return { valid: false, error: 'Email is required' };
    let v = value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return { valid: false, error: 'Enter a valid email address' };
    return { valid: true };
  }

  // ===== NAME =====
  function validateName(value, fieldName) {
    if (!value || !value.trim()) return { valid: false, error: `${fieldName || 'Name'} is required` };
    if (value.trim().length < 2) return { valid: false, error: `${fieldName || 'Name'} must be at least 2 characters` };
    if (value.trim().length > 100) return { valid: false, error: `${fieldName || 'Name'} cannot exceed 100 characters` };
    return { valid: true };
  }

  // ===== CRYPTO WALLET (ETH-style, fallback) =====
  function validateEthAddress(value) {
    if (!value) return { valid: false, error: 'Wallet address is required' };
    if (!/^0x[a-fA-F0-9]{40}$/.test(value.trim())) return { valid: false, error: 'Invalid Ethereum address (must be 0x + 40 hex chars)' };
    return { valid: true };
  }

  return {
    validatePhone,
    validateCardNumber,
    validateCVC,
    validateCardExpiry,
    validateIBAN,
    validateSWIFT,
    validateSortCode,
    validateUSRouting,
    validateSSN,
    validateEIN,
    validatePostalCode,
    validateCryptoAddress,
    validateAccountNumber,
    validateEmail,
    validateName,
    detectCardBrand,
    luhnCheck,
    PHONE_RULES,
    IBAN_LENGTHS,
    POSTAL_RULES,
  };

})();

if (typeof window !== 'undefined') window.MetasValidate = MetasValidate;
