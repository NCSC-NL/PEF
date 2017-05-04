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
package nl.minvenj.pef.exception;

/**
 * Thrown when an unsupported file format is encountered.
 *
 * @author Netherlands Forensic Institute.
 */
public class UnsupportedFileFormatException extends RuntimeException {

    private static final long serialVersionUID = 7009827606010928329L;

    public UnsupportedFileFormatException(final String message) {
        super(message);
    }

    public UnsupportedFileFormatException(final Throwable cause) {
        super(cause);
    }

    public UnsupportedFileFormatException(final String message, final Throwable cause) {
        super(message, cause);
    }
}