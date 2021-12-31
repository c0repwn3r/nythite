def hrtime(ms):
    if ms == False:
        return 'Calculating...'
    seconds=(ms/1000)%60
    seconds = int(seconds)
    minutes=(ms/(1000*60))%60
    minutes = int(minutes)
    hours = (ms/(1000*60*60))%24
    hours = int(hours)
    return f'{str(hours).zfill(2)}:{str(minutes).zfill(2)}:{str(seconds).zfill(2)}'

def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"