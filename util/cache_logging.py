"""Cache logging module for tracking cache performance.

This module provides functions for tracking cache hits and misses,
calculating cache statistics, and displaying them. It is used by
various modules in the project that implement caching mechanisms.
"""

from typing import Dict, Any

_cache_stats = {}

def initialize_cache(cache_name: str) -> None:
    """Initialize statistics for a cache.
    
    Args:
        cache_name: Name of the cache to initialize
    """
    if cache_name not in _cache_stats:
        _cache_stats[cache_name] = {
            "hits": 0,
            "misses": 0
        }

def record_hit(cache_name: str) -> None:
    """Record a cache hit.
    
    Args:
        cache_name: Name of the cache that had a hit
    """
    initialize_cache(cache_name)
    _cache_stats[cache_name]["hits"] += 1

def record_miss(cache_name: str) -> None:
    """Record a cache miss.
    
    Args:
        cache_name: Name of the cache that had a miss
    """
    initialize_cache(cache_name)
    _cache_stats[cache_name]["misses"] += 1

def get_stats(cache_name: str = None) -> Dict[str, Any]:
    """Get statistics for a specific cache or all caches.
    
    Args:
        cache_name: Name of the cache to get statistics for, or None for all caches
        
    Returns:
        Dictionary with cache statistics
    """
    if cache_name is not None:
        if cache_name not in _cache_stats:
            return {
                "hits": 0,
                "misses": 0,
                "total": 0,
                "hit_ratio": 0
            }
        
        stats = _cache_stats[cache_name]
        total = stats["hits"] + stats["misses"]
        hit_ratio = stats["hits"] / total if total > 0 else 0
        
        return {
            "hits": stats["hits"],
            "misses": stats["misses"],
            "total": total,
            "hit_ratio": hit_ratio
        }
    else:
        result = {}
        for name, stats in _cache_stats.items():
            total = stats["hits"] + stats["misses"]
            hit_ratio = stats["hits"] / total if total > 0 else 0
            
            result[name] = {
                "hits": stats["hits"],
                "misses": stats["misses"],
                "total": total,
                "hit_ratio": hit_ratio
            }
        return result

def print_stats(cache_name: str = None) -> None:
    """Print statistics for a specific cache or all caches.
    
    Args:
        cache_name: Name of the cache to print statistics for, or None for all caches
    """
    if cache_name is not None:
        stats = get_stats(cache_name)
        print(f"Cache Statistics for {cache_name}:")
        print(f"  - Hits: {stats['hits']}")
        print(f"  - Misses: {stats['misses']}")
        print(f"  - Total: {stats['total']}")
        print(f"  - Hit Ratio: {stats['hit_ratio']:.2%}")
    else:
        all_stats = get_stats()
        print("Cache Statistics:")
        for name, stats in all_stats.items():
            print(f"  - {name.replace('_', ' ').title()}:")
            print(f"    - Hits: {stats['hits']}")
            print(f"    - Misses: {stats['misses']}")
            print(f"    - Total: {stats['total']}")
            print(f"    - Hit Ratio: {stats['hit_ratio']:.2%}")