import re
import requests
from urllib.parse import urljoin

from utils.output import section, info, success, warning, error, result, table

TECH_SIGNATURES = {
    "WordPress": {
        "headers": {},
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress"],
        "cookies": ["wordpress_", "wp-settings"],
        "files": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
    },
    "Drupal": {
        "headers": {"X-Drupal-Cache": ".*", "X-Drupal-Dynamic-Cache": ".*"},
        "html": [r"drupal", r"Drupal.settings", r"/sites/default/"],
        "cookies": ["Drupal"],
        "files": ["/CHANGELOG.txt", "/sites/default/settings.php"],
    },
    "Joomla": {
        "headers": {},
        "html": [r"/media/jui/", r"com_content", r"option=com_", r"joomla"],
        "cookies": [],
        "files": ["/administrator/", "/components/", "/modules/"],
    },
    "Laravel": {
        "headers": {},
        "html": [r"laravel", r"csrf-token", r"__csrf_"],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "files": [],
    },
    "Django": {
        "headers": {},
        "html": [r"csrfmiddlewaretoken", r"__csrfmid"],
        "cookies": ["csrftoken", "sessionid"],
        "files": ["/admin/"],
    },
    "Express.js": {
        "headers": {"X-Powered-By": "Express"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "ASP.NET": {
        "headers": {"X-AspNet-Version": ".*", "X-Powered-By": "ASP.NET"},
        "html": [],
        "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
        "files": [],
    },
    "nginx": {
        "headers": {"Server": "nginx"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Apache": {
        "headers": {"Server": "Apache"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Cloudflare": {
        "headers": {"Server": "cloudflare", "CF-RAY": ".*"},
        "html": [],
        "cookies": ["__cfduid"],
        "files": [],
    },
    "Google Analytics": {
        "headers": {},
        "html": [r"gtag\(", r"ga\(", r"analytics\.js", r"google-analytics\.com"],
        "cookies": [],
        "files": [],
    },
    "jQuery": {
        "headers": {},
        "html": [r"jquery", r"jQuery\."],
        "cookies": [],
        "files": [],
    },
    "Bootstrap": {
        "headers": {},
        "html": [r"bootstrap\.", r"bootstrap-"],
        "cookies": [],
        "files": [],
    },
    "React": {
        "headers": {},
        "html": [r"react\.js", r"react\.min\.js", r"__REACT_"],
        "cookies": [],
        "files": [],
    },
    "Vue.js": {
        "headers": {},
        "html": [r"vue\.js", r"vue\.min\.js", r"__vue__"],
        "cookies": [],
        "files": [],
    },
    "Shopify": {
        "headers": {"X-ShopId": ".*"},
        "html": [r"/cdn/shop/", r"shopify"],
        "cookies": ["_shopify_", "cart_sig"],
        "files": [],
    },
    "Magento": {
        "headers": {},
        "html": [r"mage/", r"Magento_", r"var MAGENTO"],
        "cookies": ["frontend"],
        "files": [],
    },
    "Plesk": {
        "headers": {"X-Powered-By": "Plesk"},
        "html": [],
        "cookies": [],
        "files": ["/plesk-stat/"],
    },
    "cPanel": {
        "headers": {},
        "html": [r"cpanel"],
        "cookies": [],
        "files": ["/cpanel", "/cpsess"],
    },
    "Next.js": {
        "headers": {"x-powered-by": "Next.js", "x-nextjs-cache": ".*"},
        "html": [r"__NEXT_DATA__", r"/_next/static", r"next\.js"],
        "cookies": [],
        "files": [],
    },
    "Nuxt.js": {
        "headers": {},
        "html": [r"__NUXT__", r"nuxt", r"_nuxt/"],
        "cookies": [],
        "files": [],
    },
    "Gatsby": {
        "headers": {},
        "html": [r"___gatsby", r"gatsby"],
        "cookies": [],
        "files": [],
    },
    "Angular": {
        "headers": {},
        "html": [r"ng-version", r"angular", r"ng-app", r"ng-controller"],
        "cookies": [],
        "files": [],
    },
    "Svelte": {
        "headers": {},
        "html": [r"svelte", r"__svelte"],
        "cookies": [],
        "files": [],
    },
    "Ruby on Rails": {
        "headers": {"X-Powered-By": "Phusion|Ruby on Rails", "X-Runtime": ".*"},
        "html": [r"rails", r"csrf-param"],
        "cookies": ["_session"],
        "files": [],
    },
    "Flask": {
        "headers": {},
        "html": [r"flask"],
        "cookies": ["session"],
        "files": [],
    },
    "FastAPI": {
        "headers": {},
        "html": [r"fastapi", r"swagger-ui"],
        "cookies": [],
        "files": ["/docs", "/redoc", "/openapi.json"],
    },
    "Spring Boot": {
        "headers": {},
        "html": [r"spring", r"whitelabel error"],
        "cookies": [],
        "files": ["/actuator", "/actuator/health", "/actuator/info"],
    },
    "Tomcat": {
        "headers": {"Server": "Tomcat", "X-Powered-By": "Servlet"},
        "html": [],
        "cookies": [],
        "files": ["/manager/html", "/examples/"],
    },
    "JBoss/WildFly": {
        "headers": {"X-Powered-By": "JBoss|WildFly"},
        "html": [],
        "cookies": [],
        "files": ["/jmx-console/", "/web-console/", "/admin-console/"],
    },
    "Jetty": {
        "headers": {"Server": "Jetty"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "IIS": {
        "headers": {"Server": "Microsoft-IIS", "X-Powered-By": "ASP.NET"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Caddy": {
        "headers": {"Server": "Caddy"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "OpenResty": {
        "headers": {"Server": "openresty"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Traefik": {
        "headers": {"X-Forwarded-For": ".*"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "HAProxy": {
        "headers": {"X-Haproxy-Server-State": ".*"},
        "html": [],
        "cookies": ["SERVERID", "HAProxy"],
        "files": [],
    },
    "Varnish": {
        "headers": {"X-Varnish": ".*", "Via": ".*varnish", "X-Cache": "HIT|MISS"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Sentry": {
        "headers": {},
        "html": [r"sentry\.io", r"raven\.min\.js", r"Sentry\.init"],
        "cookies": [],
        "files": [],
    },
    "New Relic": {
        "headers": {},
        "html": [r"newrelic", r"NREUM"],
        "cookies": [],
        "files": [],
    },
    "Hotjar": {
        "headers": {},
        "html": [r"hotjar", r"hjSettings"],
        "cookies": ["_hj"],
        "files": [],
    },
    "Matomo": {
        "headers": {},
        "html": [r"matomo", r"piwik"],
        "cookies": ["_pk_"],
        "files": ["/matomo/", "/piwik/"],
    },
    "CloudFlare": {
        "headers": {"Server": "cloudflare", "CF-RAY": ".*"},
        "html": [],
        "cookies": ["__cfduid", "__cf_bm"],
        "files": [],
    },
    "Fastly": {
        "headers": {"X-Served-By": ".*cache", "X-Cache-Hits": ".*", "X-Timer": ".*"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Akamai": {
        "headers": {"X-Akamai-Transformed": ".*", "X-Akamai-Request-ID": ".*"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Sucuri": {
        "headers": {"X-Sucuri-ID": ".*", "X-Sucuri-Cache": ".*"},
        "html": [r"sucuri"],
        "cookies": ["sucuri_cloudproxy"],
        "files": [],
    },
    "W3 Total Cache": {
        "headers": {},
        "html": [r"W3 Total Cache", r"w3tc"],
        "cookies": ["w3tc"],
        "files": [],
    },
    "WP Super Cache": {
        "headers": {},
        "html": [r"WP-Super-Cache", r"super cache"],
        "cookies": [],
        "files": [],
    },
    "WP Engine": {
        "headers": {},
        "html": [r"wp\-engine", r"wpe\-"],
        "cookies": ["wpe_"],
        "files": [],
    },
    "Elementor": {
        "headers": {},
        "html": [r"elementor", r"e\-icon"],
        "cookies": [],
        "files": [],
    },
    "WooCommerce": {
        "headers": {},
        "html": [r"woocommerce", r"wc-", r"add_to_cart", r"woo_"],
        "cookies": ["woocommerce_"],
        "files": ["/wp-content/plugins/woocommerce/"],
    },
    "phpMyAdmin": {
        "headers": {},
        "html": [r"phpMyAdmin", r"pma_"],
        "cookies": ["phpMyAdmin", "pma_"],
        "files": ["/phpmyadmin/", "/phpMyAdmin/", "/pma/"],
    },
    "Adminer": {
        "headers": {},
        "html": [r"Adminer", r"adminer"],
        "cookies": [],
        "files": ["/adminer.php", "/adminer/"],
    },
    "phpinfo()": {
        "headers": {},
        "html": [r"phpinfo", r"PHP Version", r"Configure Command"],
        "cookies": [],
        "files": ["/info.php", "/phpinfo.php", "/test.php"],
    },
    "Swagger UI": {
        "headers": {},
        "html": [r"swagger-ui", r"SwaggerUI", r"swagger-initializer"],
        "cookies": [],
        "files": ["/swagger", "/api/docs", "/swagger-ui.html"],
    },
    "GraphQL": {
        "headers": {},
        "html": [r"graphql"],
        "cookies": [],
        "files": ["/graphql", "/graphiql", "/graphql/console"],
    },
    "Webpack": {
        "headers": {},
        "html": [r"webpack", r"__webpack_require__"],
        "cookies": [],
        "files": [],
    },
    "Vite": {
        "headers": {},
        "html": [r"vite", r"@vite"],
        "cookies": [],
        "files": [],
    },
    "Socket.io": {
        "headers": {},
        "html": [r"socket\.io", r"io\.connect"],
        "cookies": [],
        "files": ["/socket.io/"],
    },
    "Pusher": {
        "headers": {},
        "html": [r"pusher", r"Pusher\."],
        "cookies": [],
        "files": [],
    },
    "Stripe": {
        "headers": {},
        "html": [r"stripe\.com", r"Stripe\."],
        "cookies": [],
        "files": [],
    },
    "PayPal": {
        "headers": {},
        "html": [r"paypal", r"paypal\.com/sdk", r"paypalobjects"],
        "cookies": [],
        "files": [],
    },
    "reCAPTCHA": {
        "headers": {},
        "html": [r"recaptcha", r"google\.com/recaptcha", r"g-recaptcha"],
        "cookies": [],
        "files": [],
    },
    "hCaptcha": {
        "headers": {},
        "html": [r"hcaptcha", r"hcaptcha\.com"],
        "cookies": [],
        "files": [],
    },
    "Algolia": {
        "headers": {},
        "html": [r"algolia", r"algoliasearch"],
        "cookies": [],
        "files": [],
    },
    "Cloudinary": {
        "headers": {},
        "html": [r"cloudinary", r"res\.cloudinary\.com"],
        "cookies": [],
        "files": [],
    },
    "Mapbox": {
        "headers": {},
        "html": [r"mapbox", r"mapbox\.gl"],
        "cookies": [],
        "files": [],
    },
    "Google Maps": {
        "headers": {},
        "html": [r"maps\.googleapis\.com", r"google\.com/maps", r"Map"],
        "cookies": [],
        "files": [],
    },
    "OpenStreetMap": {
        "headers": {},
        "html": [r"openstreetmap", r"openlayers", r"leaflet"],
        "cookies": [],
        "files": [],
    },
    "Mailchimp": {
        "headers": {},
        "html": [r"mailchimp", r"list-manage\.com"],
        "cookies": [],
        "files": [],
    },
    "SendGrid": {
        "headers": {},
        "html": [r"sendgrid", r"sg\.js"],
        "cookies": [],
        "files": [],
    },
    "Disqus": {
        "headers": {},
        "html": [r"disqus", r"disqus\.com"],
        "cookies": [],
        "files": [],
    },
    "LiveChat": {
        "headers": {},
        "html": [r"livechat", r"livechatinc"],
        "cookies": [],
        "files": [],
    },
    "Intercom": {
        "headers": {},
        "html": [r"intercom", r"intercom\.io"],
        "cookies": [],
        "files": [],
    },
    "Zendesk": {
        "headers": {},
        "html": [r"zendesk", r"zopim"],
        "cookies": [],
        "files": [],
    },
    "Tawk.to": {
        "headers": {},
        "html": [r"tawk", r"tawk\.to"],
        "cookies": [],
        "files": [],
    },
    "Crisp Chat": {
        "headers": {},
        "html": [r"crisp\.chat", r"crisp\.im", r"CRISP_WEBSITE_ID"],
        "cookies": [],
        "files": [],
    },
    "HubSpot": {
        "headers": {},
        "html": [r"hubspot", r"hs\-", r"hs-script"],
        "cookies": ["__hstc", "hubspotutk"],
        "files": [],
    },
    "Salesforce": {
        "headers": {},
        "html": [r"salesforce", r"sfdc"],
        "cookies": [],
        "files": [],
    },
    "SAP": {
        "headers": {},
        "html": [r"sap"],
        "cookies": ["sap-"],
        "files": [],
    },
    "Oracle": {
        "headers": {"Server": "Oracle"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "IBM": {
        "headers": {"Server": "IBM_HTTP_Server"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "GoDaddy": {
        "headers": {"X-Powered-By": "GoDaddy"},
        "html": [r"godaddy"],
        "cookies": [],
        "files": [],
    },
    "Squarespace": {
        "headers": {"X-Served-By": "squarespace"},
        "html": [r"squarespace", r"static\.squarespace\.com"],
        "cookies": ["ss_s"],
        "files": [],
    },
    "Wix": {
        "headers": {"X-Wix-": ".*"},
        "html": [r"wix\.com", r"Wix\.", r"wix-static"],
        "cookies": ["wixSession"],
        "files": [],
    },
    "Weebly": {
        "headers": {},
        "html": [r"weebly", r"weebly\.com"],
        "cookies": [],
        "files": [],
    },
    "Jimdo": {
        "headers": {},
        "html": [r"jimdo", r"jimdosite"],
        "cookies": [],
        "files": [],
    },
    "Webflow": {
        "headers": {},
        "html": [r"webflow", r"webflow\.js"],
        "cookies": [],
        "files": [],
    },
    "Tilda": {
        "headers": {},
        "html": [r"tilda", r"tilda\.ws", r"tilda\.cc"],
        "cookies": [],
        "files": [],
    },
    "GitHub Pages": {
        "headers": {"Server": "GitHub.com"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "GitLab Pages": {
        "headers": {"Server": "GitLab.com"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Netlify": {
        "headers": {"Server": "Netlify"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Vercel": {
        "headers": {"X-Vercel-": ".*", "server": "Vercel"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Heroku": {
        "headers": {"X-Powered-By": "Express"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "DigitalOcean": {
        "headers": {"Server": "nginx"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Google Cloud": {
        "headers": {"Via": ".*google.*", "X-Google-": ".*"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "AWS": {
        "headers": {"X-Amz-": ".*", "X-Amzn-": ".*"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Azure": {
        "headers": {"X-Azure-Ref": ".*", "X-Powered-By": "Azure"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Alibaba Cloud": {
        "headers": {"Server": "Tengine/Aliyun"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "OpenCart": {
        "headers": {},
        "html": [r"opencart", r"oc_", r"route=common/home"],
        "cookies": ["OCSESSID"],
        "files": ["/admin/", "/catalog/"],
    },
    "PrestaShop": {
        "headers": {},
        "html": [r"prestashop", r"ps_"],
        "cookies": ["PrestaShop"],
        "files": ["/modules/", "/themes/"],
    },
    "WHMCS": {
        "headers": {},
        "html": [r"whmcs", r"WHMCS"],
        "cookies": ["WHMCS"],
        "files": ["/whmcs/", "/members/", "/clients/"],
    },
    "vBulletin": {
        "headers": {},
        "html": [r"vbulletin", r"vb_"],
        "cookies": ["bb_sessionhash", "bblastactivity"],
        "files": [],
    },
    "phpBB": {
        "headers": {},
        "html": [r"phpbb", r"phpBB"],
        "cookies": ["phpbb3_"],
        "files": [],
    },
    "XenForo": {
        "headers": {},
        "html": [r"xenforo", r"xf_"],
        "cookies": ["xf_"],
        "files": [],
    },
    "Discourse": {
        "headers": {},
        "html": [r"discourse", r"d Rails"],
        "cookies": ["_t", "_forum_session"],
        "files": [],
    },
    "Flarum": {
        "headers": {},
        "html": [r"flarum", r"flarum-"],
        "cookies": [],
        "files": [],
    },
    "MediaWiki": {
        "headers": {},
        "html": [r"mediawiki", r"mw_", r"wikieditor"],
        "cookies": [],
        "files": ["/wiki/", "/w/"],
    },
    "Confluence": {
        "headers": {"X-Confluence": ".*"},
        "html": [r"confluence", r"atl.", r"AUI"],
        "cookies": ["confluence"],
        "files": [],
    },
    "Jira": {
        "headers": {"X-AREQUESTID": ".*", "X-ASESSIONID": ".*"},
        "html": [r"jira", r"com\.atlassian\.jira"],
        "cookies": ["jira"],
        "files": ["/jira/", "/secure/"],
    },
    "GitLab": {
        "headers": {},
        "html": [r"gitlab"],
        "cookies": ["_gitlab_session"],
        "files": ["/gitlab/", "/explore"],
    },
    "Bitbucket": {
        "headers": {},
        "html": [r"bitbucket"],
        "cookies": [],
        "files": [],
    },
    "Jenkins": {
        "headers": {"X-Jenkins": ".*"},
        "html": [r"jenkins", r"Jenkins"],
        "cookies": ["jenkins-"],
        "files": ["/jenkins/", "/jenkins/login", "/script"],
    },
    "Travis CI": {
        "headers": {},
        "html": [r"travis-ci\.com", r"travis"],
        "cookies": [],
        "files": [],
    },
    "CircleCI": {
        "headers": {},
        "html": [r"circleci", r"circle-ci"],
        "cookies": [],
        "files": [],
    },
    "Grafana": {
        "headers": {},
        "html": [r"grafana"],
        "cookies": ["grafana_session"],
        "files": ["/grafana/", "/login", "/dashboard"],
    },
    "Kibana": {
        "headers": {},
        "html": [r"kibana"],
        "cookies": ["kibana"],
        "files": ["/kibana/", "/app/kibana"],
    },
    "Prometheus": {
        "headers": {},
        "html": [r"prometheus"],
        "cookies": [],
        "files": ["/metrics", "/prometheus/"],
    },
    "Elasticsearch": {
        "headers": {},
        "html": [r"elasticsearch"],
        "cookies": [],
        "files": ["/_cluster/health", "/_cat/"],
    },
    "MongoDB Express": {
        "headers": {},
        "html": [r"mongo-express", r"Mongo Express"],
        "cookies": [],
        "files": ["/mongo-express/", "/mongodb/"],
    },
    "Redis Commander": {
        "headers": {},
        "html": [r"redis-commander", r"Redis Commander"],
        "cookies": [],
        "files": [],
    },
    "phpPgAdmin": {
        "headers": {},
        "html": [r"phppgadmin", r"phpPgAdmin"],
        "cookies": [],
        "files": ["/phppgadmin/", "/phpPgAdmin/"],
    },
    "N8n": {
        "headers": {},
        "html": [r"n8n", r"n8n\.io"],
        "cookies": [],
        "files": [],
    },
    "Odoo": {
        "headers": {"X-Odoo": ".*"},
        "html": [r"odoo", r"oe_"],
        "cookies": ["session_id"],
        "files": [],
    },
    "Zabbix": {
        "headers": {},
        "html": [r"zabbix"],
        "cookies": ["zbx_sessionid"],
        "files": ["/zabbix/"],
    },
    "Nagios": {
        "headers": {},
        "html": [r"nagios"],
        "cookies": ["nagios"],
        "files": ["/nagios/", "/nagios/cgi-bin/"],
    },
    "Puppet": {
        "headers": {"X-Puppet-Version": ".*"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Chef": {
        "headers": {"X-Chef-Version": ".*"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Ansible Tower": {
        "headers": {},
        "html": [r"ansible", r"awx"],
        "cookies": [],
        "files": [],
    },
    "Kubernetes": {
        "headers": {},
        "html": [r"kubernetes", r"k8s"],
        "cookies": [],
        "files": ["/api/v1", "/api/v1/namespaces"],
    },
    "Docker": {
        "headers": {"Server": "Docker"},
        "html": [],
        "cookies": [],
        "files": [],
    },
    "Rancher": {
        "headers": {},
        "html": [r"rancher"],
        "cookies": ["R_SESS"],
        "files": ["/rancher/", "/v2-beta/"],
    },
    "Tomcat Manager": {
        "headers": {},
        "html": [r"Tomcat Manager"],
        "cookies": [],
        "files": ["/manager/html", "/host-manager/"],
    },
    "Webmin": {
        "headers": {},
        "html": [r"webmin", r"Webmin"],
        "cookies": [],
        "files": ["/webmin/", "/webmin/session_login.cgi"],
    },
    "CPanel": {
        "headers": {},
        "html": [r"cpanel"],
        "cookies": ["cpsession"],
        "files": ["/cpanel", "/cpsess"],
    },
    "Plesk": {
        "headers": {"X-Powered-By": "Plesk"},
        "html": [r"plesk"],
        "cookies": [],
        "files": ["/plesk-stat/"],
    },
    "ISPConfig": {
        "headers": {},
        "html": [r"ispconfig"],
        "cookies": [],
        "files": [],
    },
    "DirectAdmin": {
        "headers": {},
        "html": [r"directadmin"],
        "cookies": ["session"],
        "files": ["/directadmin/"],
    },
    "VestaCP": {
        "headers": {},
        "html": [r"vesta"],
        "cookies": [],
        "files": ["/vst/"],
    },
    "HestiaCP": {
        "headers": {},
        "html": [r"hestia"],
        "cookies": [],
        "files": [],
    },
    "Sentora": {
        "headers": {},
        "html": [r"sentora"],
        "cookies": [],
        "files": ["/sentora/"],
    },
    "Ajenti": {
        "headers": {},
        "html": [r"ajenti"],
        "cookies": [],
        "files": [],
    },
    "Mailcow": {
        "headers": {},
        "html": [r"mailcow"],
        "cookies": [],
        "files": [],
    },
    "Roundcube": {
        "headers": {},
        "html": [r"roundcube", r"rc_"],
        "cookies": ["roundcube_sessid"],
        "files": ["/roundcube/", "/webmail/", "/mail/"],
    },
    "SquirrelMail": {
        "headers": {},
        "html": [r"squirrelmail"],
        "cookies": ["SQMSESSID"],
        "files": ["/squirrelmail/", "/sqm/"],
    },
    "RainLoop": {
        "headers": {},
        "html": [r"rainloop", r"RainLoop"],
        "cookies": [],
        "files": [],
    },
    "SnappyMail": {
        "headers": {},
        "html": [r"snappymail"],
        "cookies": [],
        "files": [],
    },
    "Poste.io": {
        "headers": {},
        "html": [r"poste\.io"],
        "cookies": [],
        "files": [],
    },
    "ISPConfig": {
        "headers": {},
        "html": [r"ispconfig"],
        "cookies": [],
        "files": [],
    },
}


class TechDetector:
    name = "tech"
    description = "Detect technologies used on a website"

    @staticmethod
    def run(target):
        section(f"Technology Detector: {target}")

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            resp = requests.get(
                target, timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
                allow_redirects=True,
            )
            html = resp.text.lower()
            headers = resp.headers
        except requests.exceptions.RequestException as e:
            error(f"Request failed: {e}")
            return {"target": target, "error": str(e)}

        found = []

        for tech_name, sigs in TECH_SIGNATURES.items():
            score = 0
            matches = []

            for h_name, h_pattern in sigs["headers"].items():
                if h_name in headers:
                    val = headers[h_name]
                    if re.search(h_pattern, val, re.I):
                        score += 3
                        matches.append(f"header {h_name}={val[:40]}")

            for html_pattern in sigs["html"]:
                if re.search(html_pattern, html, re.I):
                    score += 2
                    matches.append(f"HTML pattern: {html_pattern}")

            for cookie_name in sigs["cookies"]:
                for cookie in resp.cookies:
                    if cookie_name in cookie.name:
                        score += 2
                        matches.append(f"cookie: {cookie.name}")
                        break

            for file_path in sigs["files"]:
                test_url = urljoin(target.rstrip("/") + "/", file_path.lstrip("/"))
                try:
                    fr = requests.head(test_url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                    if fr.status_code == 200:
                        score += 2
                        matches.append(f"accessible file: {test_url}")
                    elif fr.status_code in [301, 302, 307, 308, 401, 403]:
                        score += 1
                        matches.append(f"redirect/forbidden: {test_url}")
                except:
                    pass

            if score >= 3:
                found.append((tech_name, score, matches[:3]))

        if found:
            found.sort(key=lambda x: -x[1])
            success(f"Detected {len(found)} technology/technologies:")
            table(
                ["TECHNOLOGY", "CONFIDENCE", "EVIDENCE"],
                [(t, f"{s}/max", "; ".join(m)) for t, s, m in found]
            )
        else:
            warning("No specific technologies detected (generic or unknown stack)")

        return {"target": target, "technologies": found}
