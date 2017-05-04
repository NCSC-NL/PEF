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
package nl.minvenj.pef.serialize.constraint;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import nl.minvenj.pef.metal.packet.application.DNS;
import nl.minvenj.pef.metal.packet.internet.ICMP;
import nl.minvenj.pef.metal.packet.internet.IPv4;
import nl.minvenj.pef.metal.packet.internet.IPv6;
import nl.minvenj.pef.metal.packet.transport.UDP;

/**
 * Predefined transformer contraints.
 *
 * @author Netherlands Forensic Institute.
 */
public final class Constraints {

    /** IPv4 and DNS. */
    public static final TransformConstraint IPV4_DNS = new TransformConstraint(IPv4.FORMAT, DNS.FORMAT);

    /** IPv6 and DNS. */
    public static final TransformConstraint IPV6_DNS = new TransformConstraint(IPv6.FORMAT, DNS.FORMAT);

    /** IPv4, UDP and DNS. */
    public static final TransformConstraint IPV4_UDP_DNS = new TransformConstraint(IPv4.FORMAT, UDP.FORMAT, DNS.FORMAT);

    /** IPv6, UDP and DNS. */
    public static final TransformConstraint IPV6_UDP_DNS = new TransformConstraint(IPv6.FORMAT, UDP.FORMAT, DNS.FORMAT);

    /** ICMP and DNS. */
    public static final TransformConstraint ICMP_DNS = new TransformConstraint(ICMP.FORMAT, DNS.FORMAT);

    /** Create a map for these constraints to enable selection. */
    public static final Map<String, TransformConstraint> CONSTRAINT_MAP;
    static {
        Map<String, TransformConstraint> initConstraintMap = new HashMap<>();
        initConstraintMap.put("IPV4_DNS", IPV4_DNS);
        initConstraintMap.put("IPV6_DNS", IPV6_DNS);
        initConstraintMap.put("IPV4_UDP_DNS", IPV4_UDP_DNS);
        initConstraintMap.put("IPV6_UDP_DNS", IPV6_UDP_DNS);
        initConstraintMap.put("ICMP_DNS", ICMP_DNS);
        CONSTRAINT_MAP = Collections.unmodifiableMap(initConstraintMap);
    }

    private Constraints() {
    }
}
