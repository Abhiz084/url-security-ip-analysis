# Save as scripts/add_diverse_benign.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.crud_operations import CRUDOperations
from urllib.parse import urlparse
from loguru import logger

crud = CRUDOperations()

# Diverse benign URLs with different patterns
diverse_benign = [
    # Short URLs
    "https://www.google.com/search?q=python",
    "https://www.google.com/maps",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/feed/trending",
    "https://www.facebook.com/profile.php?id=12345",
    "https://www.facebook.com/groups/python",
    "https://www.instagram.com/p/abc123/",
    "https://www.instagram.com/explore/tags/python/",
    "https://www.twitter.com/elonmusk/status/123456",
    "https://www.twitter.com/search?q=python",
    "https://www.reddit.com/r/Python/comments/abc123/",
    "https://www.reddit.com/r/programming/",
    "https://www.linkedin.com/in/username",
    "https://www.linkedin.com/jobs/search/?keywords=python",
    
    # Longer benign URLs
    "https://www.amazon.com/dp/B08N5WRWNW/ref=sr_1_1?keywords=laptop&qid=1234567",
    "https://www.amazon.com/s?k=python+programming&ref=nb_sb_noss_2",
    "https://www.netflix.com/browse/genre/34399",
    "https://www.netflix.com/watch/80100172?trackId=13752289",
    "https://www.wikipedia.org/wiki/Python_(programming_language)",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://www.stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://www.stackoverflow.com/questions/tagged/python",
    
    # API-like benign URLs  
    "https://api.github.com/users/torvalds/repos",
    "https://api.github.com/search/repositories?q=tensorflow",
    "https://jsonplaceholder.typicode.com/posts/1",
    "https://jsonplaceholder.typicode.com/comments?postId=1",
    "https://pokeapi.co/api/v2/pokemon/ditto",
    "https://api.openweathermap.org/data/2.5/weather?q=London",
    
    # News and blogs
    "https://www.bbc.com/news/technology-12345678",
    "https://www.bbc.com/sport/football/12345678",
    "https://www.cnn.com/2024/01/15/tech/ai-advances/index.html",
    "https://www.nytimes.com/2024/01/15/technology/ai-models.html",
    "https://www.theguardian.com/technology/2024/jan/15/ai-breakthrough",
    "https://medium.com/topic/programming",
    "https://medium.com/@username/how-to-learn-python-abc123def456",
    "https://dev.to/t/python",
    "https://dev.to/username/10-python-tips-you-need-to-know-abc123",
    "https://towardsdatascience.com/machine-learning-basics-abc123",
    
    # E-commerce
    "https://www.ebay.com/itm/123456789012",
    "https://www.ebay.com/sch/i.html?_nkw=python+book",
    "https://www.etsy.com/listing/123456789/python-course",
    "https://www.shopify.com/blog/python-ecommerce",
    "https://www.walmart.com/ip/123456789",
    
    # Documentation
    "https://docs.python.org/3/tutorial/index.html",
    "https://docs.djangoproject.com/en/5.0/topics/db/models/",
    "https://flask.palletsprojects.com/en/3.0.x/quickstart/",
    "https://fastapi.tiangolo.com/tutorial/first-steps/",
    "https://scikit-learn.org/stable/modules/svm.html",
    "https://pandas.pydata.org/docs/getting_started/intro_tutorials/",
    "https://numpy.org/doc/stable/user/absolute_beginners.html",
]

logger.info(f"Adding {len(diverse_benign)} diverse benign URLs...")

saved = 0
for url in diverse_benign:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path or '/'
        
        crud.insert_url(
            full_url=url,
            domain=domain,
            path=path,
            protocol=parsed.scheme,
            tld=domain.split('.')[-1] if '.' in domain else '',
            url_length=len(url),
            source='Diverse_Benign',
            is_malicious=False  # These are all benign!
        )
        saved += 1
    except Exception as e:
        if 'Duplicate' in str(e):
            saved += 1
        else:
            logger.debug(f"Failed: {url[:50]} - {e}")

logger.info(f"Added {saved} diverse benign URLs!")
