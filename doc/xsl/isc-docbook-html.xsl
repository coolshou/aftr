<!--
 - Copyright (C) 2005,2007,2010  Internet Systems Consortium, Inc. ("ISC")
 -
 - Permission to use, copy, modify, and/or distribute this software for any
 - purpose with or without fee is hereby granted, provided that the above
 - copyright notice and this permission notice appear in all copies.
 -
 - THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 - REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 - AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 - INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 - LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 - OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 - PERFORMANCE OF THIS SOFTWARE.
-->

<!-- $Id: isc-docbook-html.xsl 962 2010-10-20 22:27:20Z pselkirk $ -->

<!-- ISC customizations for Docbook-XSL HTML generator --> 

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <!-- Import the Docbook HTML stuff -->
  <xsl:import href="/usr/local/share/xsl/docbook/html/docbook.xsl"/>

  <!-- Readable HTML output, please -->
  <xsl:output indent="yes"/>

  <!-- ANSI C function prototypes, please -->
  <xsl:param name="funcsynopsis.style">ansi</xsl:param>

  <!-- Use ranges when constructing copyrights -->
  <xsl:param name="make.year.ranges" select="1"/>

  <!-- Include our copyright generator -->
  <xsl:include href="copyright.xsl"/>

  <!-- Set comment convention for this output format -->
  <xsl:param name="isc.copyright.leader"> - </xsl:param>

  <!-- Automatic section numbering -->
  <xsl:param name="section.autolabel">1</xsl:param>
  <xsl:param name="section.autolabel.max_depth">2</xsl:param>
  <xsl:param name="section.label.includes.component.label">1</xsl:param>

  <!-- Override Docbook template to insert copyright -->
  <xsl:template name="user.preroot">
    <xsl:comment>
      <xsl:text>&#10;</xsl:text>
      <xsl:value-of select="$isc.copyright"/>
    </xsl:comment>
    <xsl:text>&#10;</xsl:text>
    <xsl:comment> &#36;Id&#36; </xsl:comment>
    <xsl:text>&#10;</xsl:text>
  </xsl:template>

</xsl:stylesheet>

<!-- 
  - Local variables:
  - mode: sgml
  - End:
 -->
