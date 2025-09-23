def invoke(peda, *args):
    """
    Sample invoke
    Usage:
        sample
    """
    (opt,) = peda.normalize_argv(args, 1)
    print('Sample plugin successfully invoked.')


invoke.options = ['option1', 'option2', 'option3']
