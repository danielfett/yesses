class YModule:
    def __init__(self, step, **kwargs):
        self.step = step
        self.__input_validation(kwargs)
        self.__create_result_dict()

    def __input_validation(self, kwargs):        
        for field, properties in self.INPUTS.items():
            self.__check_required_field(field, properties, kwargs)
            self.__check_required_keys(field, properties, kwargs)
            self.__unwrap_field(field, properties, kwargs)
            setattr(self, field, kwargs[field])

    def __check_required_field(self, field, properties, kwargs):        
        if field in kwargs:
            return
        if 'default' in properties:
            kwargs[field] = properties['default']
        else:
            raise Exception(f"Missing input to module {self.__class__.__name__}: {field}")

    def __check_required_keys(self, field, properties, kwargs):
        if properties['required_keys'] is None:
            return
        if field not in kwargs or kwargs[field] is None:
            return
        for el in kwargs[field]:
            for key in properties['required_keys']:
                try:
                    el[key]
                except KeyError:
                    raise Exception(f"In field {field}: Missing key '{key}' on input element '{el}' in {self.step}.")

    def __unwrap_field(self, field, properties, kwargs):        
        if not properties.get('unwrap', False):
            return
        assert(len(properties['required_keys']) == 1)
        kwargs[field] = list(el.get(properties['required_keys'][0]) for el in kwargs[field])
                    
    def __create_result_dict(self):
        self.results = {}
        for field, properties in self.OUTPUTS.items():
            if '*' in field or '?' in field:  # field names may contain placeholders; we skip these
                continue
            self.results[field] = []
                
    def __check_output_types(self):        
        for field, properties in self.OUTPUTS.items():
            if field not in self.results:
                raise Exception(f"Missing field {field} in output of {self.step}")
            if properties['provided_keys'] is None:
                continue
            for el in self.results[field]:
                for key in properties['provided_keys']:
                    try:
                        el[key]
                    except KeyError:
                        raise Exception(f"In field {field}: Missing key '{key}' on output element '{el}' in {self.step}.")

    def run_module(self):
        self.run()
        self.__check_output_types()
        return self.results
    
