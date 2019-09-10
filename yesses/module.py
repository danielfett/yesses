
def unwrap_key(var, key):
    def decorating_unwrap_keys(fn):
        def unwrap_keys(step, *args, **kwargs):
            out = []
            if var in kwargs and kwargs[var] is not None:
                for element in kwargs[var]:
                    if not isinstance(element, dict):
                        raise Exception(f"Expected {var} to contain dictionaries with the key '{key}', but the element '{element}' is a {type(element)}.")                       
                    try:
                        out.append(element[key])
                    except KeyError:
                        raise Exception(f"Missing key '{key}' on input element {element} in {step}.")
            kwargs[var] = out
            fn(step, *args, **kwargs)
        return unwrap_keys
    return decorating_unwrap_keys

def assert_keys(var, keys):
    def decorating_assert_keys(fn):
        def check_keys(step, *args, **kwargs):
            if var in kwargs and kwargs[var] is not None:
                for element in kwargs[var]:
                    for key in keys:
                        if not key in element:
                            raise Exception(f"Missing key '{key}' on input element {element} in {step}.")
            fn(step, *args, **kwargs)
        return check_keys
    return decorating_assert_keys
            

class YModule:
    pass

                
