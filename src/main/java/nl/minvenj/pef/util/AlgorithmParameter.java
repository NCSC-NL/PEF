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
package nl.minvenj.pef.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * Struct for parameters of algorithmic functions
 * Base class for parameters. TBD way to go...
 */
public class AlgorithmParameter {
    private final String _name;
    private final String _value;
    private final Class<?> _type;

    public AlgorithmParameter(final String name, final String value, final Class<?> type){
        _name = name;
        _value = value;
        _type = type;
    }

    public final String getName() {
        return _name;
    }

    public final String getValue() {
        return _value;
    }

    public Class<?> getType() {
        return _type;
    }

    public boolean testParameter(final String name, final Class<?> type, StringBuilder message) {
        if (!name.equals(_name)) {
            message.append("The parameter name "+ _name + " is not equal to "  + name);
            return false;
        }
        if (type != _type) {
            message.append("The parameter type "+ _type.toString() + " is not equal to "  + type.toString());
            return false;
        }
        return valueAndTypeMatch(message);
    }

    public boolean valueAndTypeMatch(StringBuilder message) {
        try {
            Constructor<?> cons = _type.getConstructor(String.class);
            cons.newInstance(_value);
        }
        catch (NoSuchMethodException methodException) {
            message.append(methodException.getMessage());
            return false;
        }
        catch (IllegalAccessException accessException) {
            message.append(accessException.getMessage());
        }
        catch (InstantiationException instantiationException) {
            message.append(instantiationException.getMessage());
            return false;
        }
        catch (InvocationTargetException invocationException) {
            message.append(invocationException.getMessage());
            return false;
        }
        return true;
    }
}
