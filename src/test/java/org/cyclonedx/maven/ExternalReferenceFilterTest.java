/*
 * This file is part of CycloneDX Maven Plugin.
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
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.cyclonedx.maven;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Metadata;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExternalReferenceFilterTest {

    private static ExternalReference reference(ExternalReference.Type type, String url) {
        final ExternalReference reference = new ExternalReference();
        reference.setType(type);
        reference.setUrl(url);
        return reference;
    }

    private static Component component(String name, ExternalReference... references) {
        final Component component = new Component();
        component.setName(name);
        component.setExternalReferences(new ArrayList<>(Arrays.asList(references)));
        return component;
    }

    @Test
    void noExpressionsMeansNothingIsLeftOut() {
        final ExternalReferenceFilter filter = new ExternalReferenceFilter(null);
        final Bom bom = new Bom();
        bom.setComponents(Collections.singletonList(
                component("a", reference(ExternalReference.Type.VCS, "https://github.com/my-org/a.git"))));

        assertTrue(filter.isEmpty());
        assertEquals(0, filter.apply(bom));
        assertEquals(1, bom.getComponents().get(0).getExternalReferences().size());
    }

    @Test
    void blankExpressionsAreIgnored() {
        assertTrue(new ExternalReferenceFilter(new String[] {"", "  ", null}).isEmpty());
    }

    @Test
    void matchingIsFindNotFullMatch() {
        final ExternalReferenceFilter filter = new ExternalReferenceFilter(new String[] {"github\\.com/my-org/"});

        assertTrue(filter.excludes(reference(ExternalReference.Type.VCS, "https://github.com/my-org/a.git/sub/module")));
        assertFalse(filter.excludes(reference(ExternalReference.Type.VCS, "https://github.com/other-org/a.git")));
        assertFalse(filter.excludes(reference(ExternalReference.Type.WEBSITE, null)));
    }

    @Test
    void leavesOutMatchingReferencesOfMetadataComponentComponentsAndNestedOnes() {
        final ExternalReferenceFilter filter = new ExternalReferenceFilter(new String[] {"github\\.com/my-org/"});

        final Component nested = component("nested", reference(ExternalReference.Type.VCS, "https://github.com/my-org/n"));
        final Component both = component("both",
                reference(ExternalReference.Type.VCS, "https://github.com/my-org/b"),
                reference(ExternalReference.Type.WEBSITE, "https://example.org/b"));
        both.setComponents(Collections.singletonList(nested));
        final Component untouched = component("untouched",
                reference(ExternalReference.Type.VCS, "https://github.com/someone/else"));
        final Component only = component("only", reference(ExternalReference.Type.VCS, "https://github.com/my-org/o"));

        final Metadata metadata = new Metadata();
        metadata.setComponent(component("app", reference(ExternalReference.Type.VCS, "https://github.com/my-org/app")));
        final Bom bom = new Bom();
        bom.setMetadata(metadata);
        final List<Component> components = new ArrayList<>(Arrays.asList(both, untouched, only));
        bom.setComponents(components);

        assertEquals(4, filter.apply(bom));

        assertNull(bom.getMetadata().getComponent().getExternalReferences());
        assertEquals(1, both.getExternalReferences().size());
        assertEquals(ExternalReference.Type.WEBSITE, both.getExternalReferences().get(0).getType());
        assertNull(nested.getExternalReferences());
        assertEquals(1, untouched.getExternalReferences().size());
        assertNull(only.getExternalReferences());
    }
}
