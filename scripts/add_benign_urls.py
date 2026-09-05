# Save and run this as scripts/add_benign_urls.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_collector.url_scraper import URLScraper

scraper = URLScraper()

# Add lots of benign URLs
print("Adding benign URLs...")
benign_urls = scraper.collect_benign_urls(200)  # Get 200 benign URLs
saved = scraper.save_to_database(benign_urls)
print(f"Added {saved} benign URLs")

# Add some more specific safe URLs
extra_benign = [
    "https://www.bing.com", "https://www.yahoo.com", "https://www.office.com",
    "https://www.adobe.com", "https://www.oracle.com", "https://www.ibm.com",
    "https://www.cisco.com", "https://www.intel.com", "https://www.amd.com",
    "https://www.nvidia.com", "https://www.stackexchange.com", "https://www.quora.com",
    "https://www.spotify.com", "https://www.netflix.com", "https://www.twitch.tv",
    "https://www.pinterest.com", "https://www.tumblr.com", "https://www.flickr.com",
    "https://www.dropbox.com", "https://www.box.com", "https://www.evernote.com",
    "https://www.notion.so", "https://www.trello.com", "https://www.asana.com",
    "https://www.slack.com", "https://www.discord.com", "https://www.zoom.us",
    "https://www.skype.com", "https://www.telegram.org", "https://www.whatsapp.com",
    "https://www.bbc.com", "https://www.cnn.com", "https://www.nytimes.com",
    "https://www.theguardian.com", "https://www.reuters.com", "https://www.bloomberg.com",
    "https://www.ebay.com", "https://www.etsy.com", "https://www.walmart.com",
    "https://www.target.com", "https://www.bestbuy.com", "https://www.homedepot.com",
    "https://www.uber.com", "https://www.airbnb.com", "https://www.booking.com",
    "https://www.expedia.com", "https://www.kayak.com", "https://www.tripadvisor.com",
]

# Parse and save extra benign URLs
from urllib.parse import urlparse
for url in extra_benign:
    parsed = urlparse(url)
    scraper.crud.insert_url(
        full_url=url,
        domain=parsed.netloc,
        path=parsed.path or '/',
        protocol=parsed.scheme,
        tld=parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
        url_length=len(url),
        source='extra_benign',
        is_malicious=False
    )

print(f"Added {len(extra_benign)} extra benign URLs")
print("\nNow run: python scripts/train_model.py")