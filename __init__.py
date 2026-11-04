def classFactory(iface):
    from .plugin import GeoServerPublisherSSOPlugin
    return GeoServerPublisherSSOPlugin(iface)
