def invoke(peda, *arg):
    """
    Sample invoke
    Usage:
        sample
    """
    print('Sample plugin successfully invoked.')


invoke.options = ['option1', 'option2', 'option3']
