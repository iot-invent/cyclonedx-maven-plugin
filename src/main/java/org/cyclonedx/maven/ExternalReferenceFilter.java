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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Leaves out the external references whose url matches one of the configured regular expressions.
 * <p>
 * The references are taken from the POMs ({@code project.url}, {@code project.scm.url}, ...), and a POM can
 * point somewhere that is not meant for the reader of the SBOM: a private repository, an internal issue
 * tracker. The plugin has no way to know, so the project says which urls to leave out
 * ({@code excludeExternalReferenceUrls}). Applies to the component the BOM describes and to every
 * component, nested ones included. A component left with no reference has none, rather than an empty list.
 */
final class ExternalReferenceFilter {

    private final List<Pattern> patterns = new ArrayList<>();

    ExternalReferenceFilter(final String[] regularExpressions) {
        if (regularExpressions != null) {
            for (final String regularExpression : regularExpressions) {
                if (regularExpression != null && !regularExpression.trim().isEmpty()) {
                    patterns.add(Pattern.compile(regularExpression.trim()));
                }
            }
        }
    }

    boolean isEmpty() {
        return patterns.isEmpty();
    }

    /** Whether the reference is to be left out: its url matches (find, not full match) any expression. */
    boolean excludes(final ExternalReference reference) {
        final String url = reference.getUrl();
        if (url == null) {
            return false;
        }
        for (final Pattern pattern : patterns) {
            if (pattern.matcher(url).find()) {
                return true;
            }
        }
        return false;
    }

    /** Removes the matching references from the BOM's metadata component and all its components; returns how many. */
    int apply(final Bom bom) {
        if (isEmpty()) {
            return 0;
        }
        int removed = 0;
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            removed += filter(bom.getMetadata().getComponent());
        }
        if (bom.getComponents() != null) {
            for (final Component component : bom.getComponents()) {
                removed += filter(component);
            }
        }
        return removed;
    }

    private int filter(final Component component) {
        int removed = 0;
        final List<ExternalReference> references = component.getExternalReferences();
        if (references != null && !references.isEmpty()) {
            final List<ExternalReference> kept = new ArrayList<>();
            for (final ExternalReference reference : references) {
                if (excludes(reference)) {
                    removed++;
                } else {
                    kept.add(reference);
                }
            }
            if (removed > 0) {
                component.setExternalReferences(kept.isEmpty() ? null : kept);
            }
        }
        if (component.getComponents() != null) {
            for (final Component nested : component.getComponents()) {
                removed += filter(nested);
            }
        }
        return removed;
    }
}
