import sys
try:
    import oqs
except Exception as e:
    print('Failed to import oqs:', e)
    sys.exit(2)
print('oqs module:', oqs)
print('\nModule dir:\n', [a for a in dir(oqs) if not a.startswith('_')])
if hasattr(oqs, 'KeyEncapsulation'):
    kc = oqs.KeyEncapsulation
    print('\nKeyEncapsulation class attributes:')
    attrs = [a for a in dir(kc) if not a.startswith('_')]
    print(attrs)
else:
    print('\nNo KeyEncapsulation class found')
if hasattr(oqs, 'Signature'):
    sg = oqs.Signature
    print('\nSignature class attributes:')
    attrs = [a for a in dir(sg) if not a.startswith('_')]
    print(attrs)
else:
    print('\nNo Signature class found')
# try to list enabled mechanisms if available
for fn in ('get_enabled_KEMs','get_enabled_kems','get_enabled_mechanisms','get_enabled_mechs'):
    if hasattr(oqs, fn):
        try:
            print('\nEnabled mechanisms via', fn, getattr(oqs, fn)())
        except Exception as e:
            print('\nCould not call', fn, e)
            
# try importing submodule oqs.oqs
try:
    import oqs.oqs as oqs_oqs
    print('\nImported oqs.oqs as oqs_oqs; dir:', [a for a in dir(oqs_oqs) if not a.startswith('_')])
    if hasattr(oqs_oqs, 'KeyEncapsulation'):
        print('oqs_oqs has KeyEncapsulation')
        try:
            inst = oqs_oqs.KeyEncapsulation('ML-KEM-512')
            im = [a for a in dir(inst) if not a.startswith('_')]
            print('\nInstance methods for oqs.oqs.KeyEncapsulation:', im)
            print('encap-like methods:', [m for m in im if 'encap' in m or 'encaps' in m or 'decap' in m or 'decaps' in m])
        except Exception as e:
            print('Could not instantiate oqs_oqs.KeyEncapsulation:', e)
    if hasattr(oqs_oqs, 'Signature'):
        print('oqs_oqs has Signature')
        try:
            inst = oqs_oqs.Signature('Dilithium3')
            im = [a for a in dir(inst) if not a.startswith('_')]
            print('\nInstance methods for oqs.oqs.Signature:', im)
            print('sign-like methods:', [m for m in im if 'sign' in m])
        except Exception as e:
            print('Could not instantiate oqs_oqs.Signature:', e)
except Exception as e:
    print('\nCould not import oqs.oqs submodule:', e)
# quick instance-level methods if classes exist
if hasattr(oqs, 'KeyEncapsulation'):
    try:
        inst = oqs.KeyEncapsulation('ML-KEM-512')
        print('\nInstance methods for KeyEncapsulation:', [a for a in dir(inst) if not a.startswith('_')])
    except Exception as e:
        print('\nCould not instantiate KeyEncapsulation:', e)
if hasattr(oqs, 'Signature'):
    try:
        inst = oqs.Signature('Dilithium3')
        print('\nInstance methods for Signature:', [a for a in dir(inst) if not a.startswith('_')])
    except Exception as e:
        print('\nCould not instantiate Signature:', e)
print('\nDone')
