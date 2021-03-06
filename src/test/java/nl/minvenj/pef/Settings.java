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
package nl.minvenj.pef;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;

public final class Settings {

    private Settings() {
    }

    /**
     * Return the relative test path.
     *
     * @return the peftest test file path
     */
    public static String getTestBasePath() {
        final URL resourceURL = Settings.class.getResource("/");
        try {
            return Paths.get(resourceURL.toURI()).toFile().getAbsolutePath();
        }
        catch (final URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }
}
