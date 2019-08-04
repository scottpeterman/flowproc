# -*- coding: utf-8 -*-
"""
tbd
"""

import logging

from pkg_resources import DistributionNotFound
from pkg_resources import get_distribution

__author__ = "Tobias Frei"
__copyright__ = "Tobias Frei"
__license__ = "mit"

logger = logging.getLogger(__name__)

# retrieve version info
try:
    dist_name = __name__
    __version__ = get_distribution(dist_name).version
except DistributionNotFound:
    __version__ = "unknown"
finally:
    del get_distribution, DistributionNotFound
