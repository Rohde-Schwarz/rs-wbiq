import numpy as np
import glob
import re
import threading

CHANNELS_TO_CHECK = 4
class TestdataCheckerThread (threading.Thread):
    def __init__(self, channel):
        threading.Thread.__init__(self)
        self.channel = channel
    
    def run(self):
        paths = glob.glob(f'/media/nvme-stripe/capture_{self.channel}_*.bin')
        paths.sort(key=lambda var:[int(x) if x.isdigit() else x for x in re.findall(r'[^0-9]|[0-9]+', var)])
        last_counter_of_previous_file = 0
        print(f'Checking channel {self.channel}.')
        if not paths:
            print(f'Channel {self.channel} has no data.')

        for file_idx, path in enumerate(paths):
            iq = np.fromfile(path, dtype=np.uint16)
            iq = np.reshape(iq, (-1, 4)).T
            print(f'Checking file {file_idx} of {len(paths)}.')
            for idx in range(4):
                assert (np.any(iq[idx] & 0xF000 == 0x1000 * (idx + 1))) # check the channel order
                counter_only = iq[idx] & ~0xF000 #read the actual counters
                diffs = np.diff(counter_only)  # the data generator counts up to 2**12-1
                indexes = np.argwhere(diffs != 1)  # so diffs should always be 1 or 4095
                diffout = counter_only[indexes]
                assert np.all(diffout == 4095)
                if file_idx != 0:
                    if last_counter_of_previous_file == 4095:
                        counter_only[0] == 0
                    else:
                        assert counter_only[0] == last_counter_of_previous_file + 1
                last_counter_of_previous_file = counter_only[-1]
        print(f'Channel {self.channel} is OK.')

if __name__ == '__main__':
    threads = []
    for channel in range(CHANNELS_TO_CHECK):
        t = TestdataCheckerThread(channel=channel)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()