package com.virgilsecurity;

import java.io.ByteArrayInputStream;

/**
 * Byte array input stream that has no available data by first request.
 */
public class SlowByteArrayInputStream extends ByteArrayInputStream {

    private boolean noData = true;

    public SlowByteArrayInputStream(byte[] bytes) {
        super(bytes);
    }

    public SlowByteArrayInputStream(byte[] bytes, int i, int i1) {
        super(bytes, i, i1);
    }

    @Override
    public synchronized int available() {
        if (this.noData) {
            this.noData = false;
            return 0;
        }
        return super.available();
    }
}
