from utils.formatting import sizeof_fmt, hrtime

from time import perf_counter
import sys

progresslist = [
    '[          ] 0% complete',
    '[          ] 1% complete',
    '[          ] 2% complete',
    '[          ] 3% complete',
    '[          ] 4% complete',
    '[          ] 5% complete',
    '[          ] 6% complete',
    '[          ] 7% complete',
    '[          ] 8% complete',
    '[          ] 9% complete',
    '[>         ] 10% complete',
    '[>         ] 11% complete',
    '[>         ] 12% complete',
    '[>         ] 13% complete',
    '[>         ] 14% complete',
    '[>         ] 15% complete',
    '[>         ] 16% complete',
    '[>         ] 17% complete',
    '[>         ] 18% complete',
    '[>         ] 19% complete',
    '[=>        ] 20% complete',
    '[=>        ] 21% complete',
    '[=>        ] 22% complete',
    '[=>        ] 23% complete',
    '[=>        ] 24% complete',
    '[=>        ] 25% complete',
    '[=>        ] 26% complete',
    '[=>        ] 27% complete',
    '[=>        ] 28% complete',
    '[=>        ] 29% complete',
    '[==>       ] 31% complete',
    '[==>       ] 32% complete',
    '[==>       ] 33% complete',
    '[==>       ] 34% complete',
    '[==>       ] 35% complete',
    '[==>       ] 36% complete',
    '[==>       ] 37% complete',
    '[==>       ] 38% complete',
    '[==>       ] 39% complete',
    '[===>      ] 40% complete',
    '[===>      ] 41% complete',
    '[===>      ] 42% complete',
    '[===>      ] 43% complete',
    '[===>      ] 44% complete',
    '[===>      ] 45% complete',
    '[===>      ] 46% complete',
    '[===>      ] 47% complete',
    '[===>      ] 48% complete',
    '[===>      ] 49% complete',
    '[====>     ] 50% complete',
    '[====>     ] 51% complete',
    '[====>     ] 52% complete',
    '[====>     ] 53% complete',
    '[====>     ] 54% complete',
    '[====>     ] 55% complete',
    '[====>     ] 56% complete',
    '[====>     ] 57% complete',
    '[====>     ] 58% complete',
    '[====>     ] 59% complete',
    '[=====>    ] 60% complete',
    '[=====>    ] 61% complete',
    '[=====>    ] 62% complete',
    '[=====>    ] 63% complete',
    '[=====>    ] 64% complete',
    '[=====>    ] 65% complete',
    '[=====>    ] 66% complete',
    '[=====>    ] 67% complete',
    '[=====>    ] 68% complete',
    '[=====>    ] 69% complete',
    '[======>   ] 70% complete',
    '[======>   ] 71% complete',
    '[======>   ] 72% complete',
    '[======>   ] 73% complete',
    '[======>   ] 74% complete',
    '[======>   ] 75% complete',
    '[======>   ] 76% complete',
    '[======>   ] 77% complete',
    '[======>   ] 78% complete',
    '[======>   ] 79% complete',
    '[=======>  ] 80% complete',
    '[=======>  ] 81% complete',
    '[=======>  ] 82% complete',
    '[=======>  ] 83% complete',
    '[=======>  ] 84% complete',
    '[=======>  ] 85% complete',
    '[=======>  ] 86% complete',
    '[=======>  ] 87% complete',
    '[=======>  ] 88% complete',
    '[=======>  ] 89% complete',
    '[========> ] 90% complete',
    '[========> ] 91% complete',
    '[========> ] 92% complete',
    '[========> ] 93% complete',
    '[========> ] 94% complete',
    '[========> ] 95% complete',
    '[========> ] 96% complete',
    '[========> ] 97% complete',
    '[========> ] 98% complete',
    '[========> ] 99% complete',
    '[=========>] 100% complete',
]


def print_progress(name, size, filecount, totalcount, amtleft, eta, starttime):
    progress = int(round((filecount / totalcount) * 100))
    try:
        string = f'{progresslist[progress]} | compressing file {name} ({sizeof_fmt(size)}) | {filecount}/{totalcount}, {sizeof_fmt(amtleft)}left, time: {hrtime(eta)}/{hrtime((perf_counter()-starttime)*1000)}                                                '
    except IndexError:
        string = f'{progresslist[-1]} | compressing file {name} ({sizeof_fmt(size)}) | {filecount}/{totalcount}, {sizeof_fmt(amtleft)}left, time: {hrtime(eta)}/{hrtime((perf_counter()-starttime)*1000)}                                                '
    string += '\r'
    print(string.replace('\n', ''), end='')
    sys.stdout.flush()


def on_progress(name, position, size):
    progress = int(round((position / size) * 100))
    string = f'{progresslist[progress]} | compressing file {name}\r'
    print(string.replace('\n', ''), end='')
    sys.stdout.flush()
