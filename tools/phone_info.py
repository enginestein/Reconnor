import re
import requests
import json
from urllib.parse import quote
from utils.output import section, info, success, warning, error, result, table

PHONE_REGEX = re.compile(r'^\+?1?\d{7,15}$')
US_PHONE = re.compile(r'^\+?1?(\d{3})(\d{3})(\d{4})$')
INTL_PREFIXES = {
    1: "US/Canada", 7: "Russia", 20: "Egypt", 27: "South Africa",
    30: "Greece", 31: "Netherlands", 32: "Belgium", 33: "France",
    34: "Spain", 36: "Hungary", 39: "Italy", 40: "Romania",
    41: "Switzerland", 42: "Czech Republic", 43: "Austria",
    44: "United Kingdom", 45: "Denmark", 46: "Sweden", 47: "Norway",
    48: "Poland", 49: "Germany", 51: "Peru", 52: "Mexico",
    53: "Cuba", 54: "Argentina", 55: "Brazil", 56: "Chile",
    57: "Colombia", 58: "Venezuela", 60: "Malaysia", 61: "Australia",
    62: "Indonesia", 63: "Philippines", 64: "New Zealand",
    65: "Singapore", 66: "Thailand", 81: "Japan", 82: "South Korea",
    84: "Vietnam", 86: "China", 90: "Turkey", 91: "India",
    92: "Pakistan", 93: "Afghanistan", 94: "Sri Lanka",
    95: "Myanmar", 98: "Iran", 212: "Morocco", 213: "Algeria",
    216: "Tunisia", 217: "Libya", 218: "Libya", 220: "Gambia",
    221: "Senegal", 222: "Mauritania", 223: "Mali", 224: "Guinea",
    225: "Ivory Coast", 226: "Burkina Faso", 227: "Niger",
    228: "Togo", 229: "Benin", 230: "Mauritius", 231: "Liberia",
    232: "Sierra Leone", 233: "Ghana", 234: "Nigeria",
    235: "Chad", 236: "Central Africa", 237: "Cameroon",
    238: "Cape Verde", 239: "Sao Tome", 240: "Equatorial Guinea",
    241: "Gabon", 242: "Congo", 243: "DR Congo", 244: "Angola",
    245: "Guinea-Bissau", 246: "Diego Garcia", 247: "Ascension",
    248: "Seychelles", 249: "Sudan", 250: "Rwanda",
    251: "Ethiopia", 252: "Somalia", 253: "Djibouti",
    254: "Kenya", 255: "Tanzania", 256: "Uganda",
    257: "Burundi", 258: "Mozambique", 260: "Zambia",
    261: "Madagascar", 262: "Reunion", 263: "Zimbabwe",
    264: "Namibia", 265: "Malawi", 266: "Lesotho",
    267: "Botswana", 268: "Swaziland", 269: "Comoros",
    290: "St Helena", 291: "Eritrea", 297: "Aruba",
    298: "Faroe Islands", 299: "Greenland",
    350: "Gibraltar", 351: "Portugal", 352: "Luxembourg",
    353: "Ireland", 354: "Iceland", 355: "Albania",
    356: "Malta", 357: "Cyprus", 358: "Finland",
    359: "Bulgaria", 370: "Lithuania", 371: "Latvia",
    372: "Estonia", 373: "Moldova", 374: "Armenia",
    375: "Belarus", 376: "Andorra", 377: "Monaco",
    378: "San Marino", 379: "Vatican", 380: "Ukraine",
    381: "Serbia", 382: "Montenegro", 383: "Kosovo",
    385: "Croatia", 386: "Slovenia", 387: "Bosnia",
    389: "Macedonia", 420: "Czech", 421: "Slovakia",
    423: "Liechtenstein", 500: "Falkland", 501: "Belize",
    502: "Guatemala", 503: "El Salvador", 504: "Honduras",
    505: "Nicaragua", 506: "Costa Rica", 507: "Panama",
    508: "St Pierre", 509: "Haiti", 590: "Guadeloupe",
    591: "Bolivia", 592: "Guyana", 593: "Ecuador",
    594: "French Guiana", 595: "Paraguay", 596: "Martinique",
    597: "Suriname", 598: "Uruguay", 599: "Netherlands Antilles",
    670: "East Timor", 672: "Antarctica", 673: "Brunei",
    674: "Nauru", 675: "Papua New Guinea", 676: "Tonga",
    677: "Solomon Islands", 678: "Vanuatu", 679: "Fiji",
    680: "Palau", 681: "Wallis", 682: "Cook Islands",
    683: "Niue", 684: "American Samoa", 685: "Samoa",
    686: "Kiribati", 687: "New Caledonia", 688: "Tuvalu",
    689: "French Polynesia", 690: "Tokelau", 691: "Micronesia",
    692: "Marshall Islands", 800: "Toll Free", 808: "Shared Cost",
    850: "North Korea", 852: "Hong Kong", 853: "Macau",
    855: "Cambodia", 856: "Laos", 860: "N. Korea",
    870: "Inmarsat", 878: "Personal", 880: "Bangladesh",
    881: "Global Sat", 882: "International", 883: "International",
    886: "Taiwan", 888: "Toll Free", 960: "Maldives",
    961: "Lebanon", 962: "Jordan", 963: "Syria",
    964: "Iraq", 965: "Kuwait", 966: "Saudi Arabia",
    967: "Yemen", 968: "Oman", 970: "Palestine",
    971: "UAE", 972: "Israel", 973: "Bahrain",
    974: "Qatar", 975: "Bhutan", 976: "Mongolia",
    977: "Nepal", 992: "Tajikistan", 993: "Turkmenistan",
    994: "Azerbaijan", 995: "Georgia", 996: "Kyrgyzstan",
    998: "Uzbekistan",
}

CARRIER_DB = {
    "US": {
        "310": ["Verizon", "AT&T", "T-Mobile", "Sprint"],
        "311": ["Verizon", "AT&T", "T-Mobile"],
        "312": ["Verizon", "Sprint"],
        "313": ["T-Mobile", "AT&T"],
        "316": ["Sprint", "Nextel"],
    },
}


class PhoneInfo:
    name = "phone-info"
    description = "Phone number intelligence: country, carrier, line type, location, reputation, and number pattern analysis"

    @staticmethod
    def run(target, timeout=10):
        section(f"Phone Number Intelligence: {target}")

        raw_number = target.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "").replace(".", "")
        if not raw_number.startswith("+"):
            if raw_number.startswith("00"):
                raw_number = "+" + raw_number[2:]
            elif raw_number.startswith("0"):
                raw_number = raw_number[1:]
                warning("Number starts with 0 — assuming national format, try with + for international")
            else:
                raw_number = raw_number

        number_info = {"raw": raw_number, "carrier": None, "country": None, "line_type": None, "location": None, "valid": False, "reputation": {}}

        section("Phase 1: Number Validation & Format Analysis")
        digits_only = re.sub(r"[^\d]", "", raw_number.replace("+", ""))
        info(f"Digits only: {digits_only}")
        info(f"Length: {len(digits_only)} digits")

        if len(digits_only) < 7 or len(digits_only) > 15:
            error(f"Invalid phone number length ({len(digits_only)} digits)")
            number_info["valid"] = False
        else:
            number_info["valid"] = True
            success(f"Number is structurally valid")

            if digits_only.startswith("1") and len(digits_only) == 11:
                area_code = digits_only[1:4]
                number_info["country_code"] = "1"
                info(f"US/Canada number detected (area code: {area_code})")
                number_info["country"] = "United States/Canada"
                number_info["location"] = PhoneInfo.lookup_area_code(area_code)
                number_info["formatted"] = f"+1 ({area_code}) {digits_only[4:7]}-{digits_only[7:]}"
                result("Formatted", number_info["formatted"])
                result("Area Code", area_code)
                result("Region", number_info["location"] or "Unknown")

            prefix = ""
            for length in range(1, 5):
                if len(digits_only) > length:
                    prefix = digits_only[:length]
                    if int(prefix) in INTL_PREFIXES:
                        number_info["country_code"] = prefix
                        number_info["country"] = INTL_PREFIXES[int(prefix)]
                        result("International Prefix", f"+{prefix}")
                        result("Country", INTL_PREFIXES[int(prefix)])
                        break

        section("Phase 2: Carrier & Line Type Detection")
        try:
            resp = requests.get(
                f"http://apilayer.net/api/validate?access_key=&number={raw_number}",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}
            )
        except:
            pass

        info("Carrier/line type lookup requires a paid API (Numverify, AbstractAPI, Twilio)")
        info("Checking via free methods...")

        try:
            resp = requests.get(
                f"https://json.geoiplookup.io/{raw_number}",
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("country_name"):
                    number_info["country"] = data.get("country_name", number_info["country"])
                    number_info["location"] = data.get("city", number_info.get("location"))
                    number_info["isp"] = data.get("isp", "")
                    result("ISP", number_info.get("isp", "N/A"))
        except:
            pass

        section("Phase 3: Phone Number Pattern Analysis")
        results_table = []

        if number_info.get("country_code") == "1" and len(digits_only) == 11:
            results_table.append(["Format", "(XXX) XXX-XXXX"])
            results_table.append(["Type", "NANP (North American Numbering Plan)"])

        if number_info.get("country"):
            results_table.append(["Country", number_info["country"]])
        results_table.append(["Length", str(len(digits_only))])
        results_table.append(["Has International Prefix", "Yes" if number_info.get("country_code") else "No"])

        repeated = re.findall(r"(.)\1{3,}", digits_only)
        if repeated:
            results_table.append(["Repeating Digits", "Yes"])
            warning("Number contains repeating digits — may be a temporary/disposable number")

        sequential = re.search(r"012345|123456|234567|345678|456789|567890", digits_only)
        if sequential:
            results_table.append(["Sequential Pattern", "Yes"])
            warning("Number contains sequential pattern — may be a test/disposable number")

        if results_table:
            table(["Property", "Value"], results_table)

        section("Phase 4: Online Reputation & Associated Data")
        search_urls = [
            f"https://www.google.com/search?q={quote(raw_number)}",
            f"https://www.bing.com/search?q={quote(raw_number)}",
        ]
        for search_url in search_urls:
            try:
                resp = requests.get(search_url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                engine = "Google" if "google" in search_url else "Bing"
                if raw_number in resp.text or digits_only in resp.text:
                    info(f"  [{engine}] Number found online")
            except:
                pass

        spam_check_urls = [
            f"https://www.800notes.com/Phone.aspx/{digits_only}",
            f"https://www.spamcalls.net/en/phone/{digits_only}",
        ]
        for spam_url in spam_check_urls:
            try:
                resp = requests.get(spam_url, timeout=timeout,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"})
                if resp.status_code == 200 and "spam" in resp.text.lower() or "scam" in resp.text.lower():
                    warning(f"  Reports found: {spam_url.split('/')[-1]} may be reported as spam/scam")
            except:
                pass

        section("Phone Number Intelligence Summary")
        result("Number", raw_number)
        result("Valid", str(number_info["valid"]))
        result("Country", number_info.get("country", "Unknown"))
        result("Region/Location", number_info.get("location", "Unknown"))
        result("Line Type", number_info.get("line_type", "Unknown (requires paid API)"))

        return number_info

    @staticmethod
    def lookup_area_code(area_code):
        area_codes = {
            "201": "NJ", "202": "DC", "203": "CT", "204": "MB", "205": "AL",
            "206": "WA", "207": "ME", "208": "ID", "209": "CA", "210": "TX",
            "212": "NYC", "213": "Los Angeles", "214": "Dallas", "215": "Philadelphia",
            "216": "Cleveland", "217": "IL", "218": "MN", "219": "IN",
            "301": "MD", "302": "DE", "303": "Denver", "304": "WV", "305": "Miami",
            "306": "SK", "307": "WY", "308": "NE", "309": "IL",
            "310": "Los Angeles", "312": "Chicago", "313": "Detroit", "314": "St Louis",
            "315": "NY", "316": "KS", "317": "Indianapolis", "318": "LA",
            "319": "IA", "320": "MN", "321": "FL", "323": "Los Angeles",
            "325": "TX", "330": "OH", "331": "Chicago", "334": "AL",
            "336": "NC", "337": "LA", "339": "MA", "340": "VI", "341": "CA",
            "347": "NYC", "351": "MA", "352": "Gainesville", "360": "WA",
            "361": "TX", "364": "KY", "380": "OH", "385": "UT",
            "401": "RI", "402": "NE", "403": "AB", "404": "Atlanta", "405": "OK",
            "406": "MT", "407": "Orlando", "408": "San Jose", "409": "TX",
            "410": "Baltimore", "412": "Pittsburgh", "413": "MA", "414": "Milwaukee",
            "415": "San Francisco", "416": "Toronto", "417": "MO", "418": "QC",
            "419": "OH", "423": "TN", "424": "Los Angeles", "425": "WA",
            "430": "TX", "432": "TX", "434": "VA", "435": "UT", "437": "Toronto",
            "438": "QC", "440": "OH", "442": "CA", "443": "MD",
            "501": "AR", "502": "KY", "503": "Portland", "504": "New Orleans",
            "505": "NM", "506": "NB", "507": "MN", "508": "MA", "509": "WA",
            "510": "Oakland", "512": "Austin", "513": "Cincinnati", "514": "Montreal",
            "515": "IA", "516": "Long Island", "517": "MI", "518": "NY",
            "519": "ON", "520": "AZ", "530": "CA", "540": "VA",
            "541": "OR", "551": "NJ", "559": "CA", "561": "FL", "562": "Long Beach",
            "563": "IA", "564": "WA", "567": "OH", "570": "PA", "571": "VA",
            "572": "OK", "573": "MO", "574": "IN", "575": "NM", "580": "OK",
            "585": "NY", "586": "MI", "587": "AB", "601": "MS", "602": "Phoenix",
            "603": "NH", "604": "Vancouver", "605": "SD", "606": "KY",
            "607": "NY", "608": "WI", "609": "NJ", "610": "PA", "612": "Minneapolis",
            "613": "Ottawa", "614": "Columbus", "615": "Nashville", "616": "MI",
            "617": "Boston", "618": "IL", "619": "San Diego", "620": "KS",
            "623": "Phoenix", "626": "Pasadena", "627": "CA", "628": "CA",
            "630": "IL", "631": "Long Island", "636": "MO", "640": "NJ",
            "641": "IA", "646": "NYC", "647": "Toronto", "650": "Palo Alto",
            "651": "MN", "657": "CA", "660": "MO", "661": "Bakersfield",
            "662": "MS", "667": "MD", "669": "San Jose", "678": "Atlanta",
            "680": "NY", "681": "WV", "682": "Dallas",
            "701": "ND", "702": "Las Vegas", "703": "Virginia", "704": "Charlotte",
            "705": "ON", "706": "GA", "707": "CA", "708": "IL", "709": "NL",
            "710": "US Gov", "712": "IA", "713": "Houston", "714": "Orange County",
            "715": "WI", "716": "Buffalo", "717": "PA", "718": "NYC",
            "719": "CO", "720": "Denver", "724": "PA", "725": "Las Vegas",
            "727": "FL", "731": "TN", "732": "NJ", "734": "MI", "737": "Austin",
            "740": "OH", "743": "NC", "747": "Los Angeles", "754": "FL",
            "757": "VA", "760": "CA", "762": "GA", "763": "MN", "764": "CA",
            "765": "IN", "769": "MS", "770": "Atlanta", "772": "FL",
            "773": "Chicago", "774": "MA", "775": "NV", "778": "BC",
            "779": "IL", "781": "MA", "782": "NS", "784": "VC",
            "785": "KS", "786": "Miami", "787": "PR", "801": "Salt Lake City",
            "802": "VT", "803": "SC", "804": "VA", "805": "Santa Barbara",
            "806": "TX", "807": "ON", "808": "Hawaii", "809": "DR",
            "810": "MI", "812": "IN", "813": "Tampa", "814": "PA",
            "815": "IL", "816": "Kansas City", "817": "Fort Worth", "818": "San Fernando",
            "819": "QC", "820": "CA", "828": "NC", "829": "DR",
            "830": "TX", "831": "Monterey", "832": "Houston", "843": "SC",
            "844": "Toll Free", "845": "NY", "847": "IL", "848": "NJ",
            "850": "FL", "854": "SC", "855": "Toll Free", "856": "NJ",
            "857": "Boston", "858": "San Diego", "859": "KY", "860": "CT",
            "861": "IN", "862": "NJ", "863": "FL", "864": "SC", "865": "TN",
            "866": "Toll Free", "867": "YT/NT/NU", "868": "TT",
            "869": "KN", "870": "AR", "872": "Chicago", "873": "QC",
            "876": "JM", "877": "Toll Free", "878": "PA", "880": "Toll Free",
            "881": "Toll Free", "882": "Toll Free", "883": "Toll Free",
            "886": "Toll Free", "887": "Toll Free", "888": "Toll Free",
            "889": "Toll Free", "900": "Premium", "901": "Memphis",
            "902": "NS", "903": "TX", "904": "Jacksonville", "905": "ON",
            "906": "MI", "907": "AK", "908": "NJ", "909": "San Bernardino",
            "910": "NC", "911": "Emergency", "912": "GA", "913": "Kansas City KS",
            "914": "Westchester", "915": "El Paso", "916": "Sacramento",
            "917": "NYC", "918": "Tulsa", "919": "Raleigh", "920": "WI",
            "925": "Concord", "928": "AZ", "929": "NYC", "930": "IN",
            "931": "TN", "934": "NY", "935": "CA",
            "936": "TX", "937": "Dayton", "938": "AL", "939": "PR",
            "940": "TX", "941": "Sarasota", "947": "MI", "949": "Irvine",
            "951": "Riverside", "952": "MN", "954": "FL", "956": "TX",
            "959": "CT", "970": "CO", "971": "Portland", "972": "Dallas",
            "973": "NJ", "978": "MA", "979": "TX", "980": "Charlotte",
            "984": "NC", "985": "LA", "986": "ID", "989": "MI",
        }
        return area_codes.get(area_code, "Unknown")
