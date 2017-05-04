/**
 * Copyright 2016 National Cyber Security Centre, Netherlands Forensic Institute
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.minvenj.pef.pseudo.dump.cap.pcapng;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.sun.org.apache.xpath.internal.compiler.PsuedoNames;

import io.parsingdata.metal.data.ParseResult;
import io.parsingdata.metal.encoding.Encoding;
import nl.minvenj.pef.metal.dump.PCAPNG;
import nl.minvenj.pef.metal.stream.InputStreamByteStream;
import nl.minvenj.pef.pseudo.FramePseudonymizer;
import nl.minvenj.pef.util.Util;

/**
 * Multi-threaded version of a PCAPNG pseudonymizer.
 *
 * @author Netherlands Forensic Institute.
 */
public class MultiThreadedPCAPNGPseudonymizer extends PCAPNGPseudonymizer {

    private final Queue<FramePseudonymizer> _framePseudonimyzers;

    /**
     * Create a new PCAPNGPseudonymizer using given framepseudonymizers to pseudonymize the frame data.
     *
     * @param framePseudonymizers the pseudonymizers to use to transform frame data
     */
    public MultiThreadedPCAPNGPseudonymizer(final List<FramePseudonymizer> framePseudonymizers) {
        _framePseudonimyzers = new ConcurrentLinkedQueue<>(framePseudonymizers);
    }

    @Override
    public File pseudonymize(final File inFile, final File outFile) throws IOException {
        try (final InputStreamByteStream input = new InputStreamByteStream(new FileInputStream(inFile));
             final OutputStream output = new BufferedOutputStream(new FileOutputStream(outFile), BUFFER_SIZE)) {

            long offset = 0;
            Encoding encoding = null;

            final ExecutorService pool = Executors.newFixedThreadPool(_framePseudonimyzers.size());
            final List<Future<byte[]>> futures = new ArrayList<>();

            while (true) {
                ParseResult result = Util.parse(input, offset, PCAPNG.SECTION_HEADER_CHO);

                if (result.succeeded) {
                    encoding = getSectionEncoding(result);
                }
                else {
                    result = Util.parse(input, offset, PCAPNG.BLOCK, encoding);
                }

                if (!result.succeeded) {
                    break;
                }

                futures.add(pool.submit(new BlockHandlerTask(result, _framePseudonimyzers)));

                offset = result.environment.offset;
            }

            pool.shutdown();
            for (final Future<byte[]> future : futures) {
                output.write(future.get());
            }
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS);
        }
        catch (final InterruptedException | ExecutionException e) {
            // TODO PEF-61 add logging
            throw new IllegalStateException(e);
        }

        return outFile;
    }

    private class BlockHandlerTask implements Callable<byte[]> {

        private final ParseResult _result;
        private final Queue<FramePseudonymizer> _pseudonymizers;

        BlockHandlerTask(final ParseResult result, final Queue<FramePseudonymizer> framePseudonimyzers) {
            _result = result;
            _pseudonymizers = framePseudonimyzers;
        }

        @Override
        public byte[] call() throws Exception {
            final FramePseudonymizer pseudonymizer = _pseudonymizers.poll();
            final byte[] blockBytes = getPseudonymizedBlockBytes(pseudonymizer, _result);
            _pseudonymizers.add(pseudonymizer);
            return blockBytes;
        }
    }
}
