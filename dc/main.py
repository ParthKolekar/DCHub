import os, sys
from .hub import DCHub

if os.name == 'posix':
    try:
        import grp
        import pwd
    except ImportError: pass

__version__ = '0.2.4'
myinfoformat = '$MyINFO $ALL %s %s%s$ $%s%s$%s$%i$|'
# Make sure bots can import DCHub under chroot without sys.path trickery
#_mod = __import__('DCHub')

def parseargs():
    '''Parses keyword arguments given on the command line'''
    options = {}
    opts = [opt for opt in ' '.join(sys.argv[1:]).split('--') if opt != '']
    for opt in opts:
        try: opt, value = opt.split('=',1)
        except ValueError:
            value = '1'
        options[opt] = value.strip()
    return options

def reloadhub(hub):
    '''Reload hub, including reloading all related modules

    Any related modules that need to be reloaded when the hub is reloaded
    should be appended to hub.reloadmodules.  Make sure that modules with
    subclasses appear later in the list than modules on which they depend.
    In general, all subclasses of DCHub (which are stored in their own
    modules), should append the name of their module to self.reloadmodules
    after running DCHub.setupdefaults.  In all cases the name of the subclass
    must be the same as the name of the module.

    This function creates a new hub from the reloaded modules, and copies the
    attributes from the old hub to the new hub, unless the atributes are
    callable or are listed in newhub.nonreloadableattrs.  If you are creating a
    subclass of DCHub and there are attributes that should not be copied to the
    reloaded hub, make sure you add the names of the attributes to the
    nonreloadableattrs set.

    Because of this behavior, simply modifying the default variable values in
    setupdefaults will not change the values for the reloaded hub (since it
    will copy over the old values).  Either add these values to the
    nonreloadableattrs set or put new values in hub.postreload(), or
    change the values before or after the reload using a bot such as PythonBot.

    Note that reloading can and most likely will break subclasses that
    aren't designed for it, and the problems can be tricky to fix.
    '''
    # Reload all necessary modules in the correct order
    modulename = 'DCHub'
    module = __import__(modulename)
    for modulename in hub.reloadmodules:
        module = reload(__import__(modulename))
        hub.log.log(hub.loglevels['hubstatus'], 'Reloaded module %s' % modulename)
    return getattr(module, modulename)(oldhub=hub)

def run(Hub = DCHub):
    '''Run the direct connect hub with keyword arguments given on the command line'''
    options = parseargs()
    dchub = Hub(**options)
    dchub.mainloop()
    while dchub.reloadonexit:
        try:
            reload(sys.modules['DCHub'])
            dchub.log.log(dchub.loglevels['hubstatus'], 'Reloaded module DCHub')
            dchub = sys.modules['DCHub'].reloadhub(dchub)
        except:
            dchub.handlereloaderror()
        dchub.mainloop()
    dchub.log.log(dchub.loglevels['hubstatus'], 'Shutting down logging system')
    logging.shutdown()

if __name__ == '__main__':
    run()
