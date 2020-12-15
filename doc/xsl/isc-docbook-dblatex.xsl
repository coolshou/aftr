<!--
 - Copyright (C) 2009  Internet Systems Consortium, Inc. ("ISC")
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

<!-- $Id: isc-docbook-dblatex.xsl 521 2009-12-03 12:34:33Z fdupont $ -->

<!-- ISC customizations for dblatex generator --> 

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <!-- LaTeX2e documentclass options. -->
  <!-- if print
  <xsl:param name="latex.class.options">10pt,twoside,openright</xsl:param>
  -->

  <!-- ANSI C function prototypes, please -->
  <xsl:param name="funcsynopsis.style">ansi</xsl:param>

  <!-- Use ranges when constructing copyrights -->
  <xsl:param name="make.year.ranges" select="1"/>

  <!-- No LoF/LoC -->
  <xsl:param name="doc.lot.show"></xsl:param>

  <!-- Put the term description on the next line -->
  <xsl:param name="term.breakline" select="1"/>

  <!-- No collaborator page -->
  <xsl:param name="doc.collab.show" select="0"/>

  <!-- No revision history too/yet -->
  <xsl:param name="latex.output.revhistory" select="0"/>

  <!-- Better hyphenation -->
  <xsl:param name="monoseq.hyphenation">nohyphen</xsl:param>

  <!-- Include our copyright generator -->
  <xsl:include href="copyright.xsl"/>

  <!-- Set comment convention for this output format -->
  <xsl:param name="isc.copyright.leader">% </xsl:param>

  <!-- Intercept top level to prepend copyright -->
  <xsl:template match="/">
    <xsl:value-of select="$isc.copyright"/>
    <xsl:apply-imports/>
  </xsl:template>

  <!-- Redefine the copyright handling -->
  <xsl:template match="copyright" mode="titlepage.mode">
    <xsl:text>\hspace{3cm} \large </xsl:text>
    <xsl:call-template name="gentext">
      <xsl:with-param name="key" select="'Copyright'"/>
    </xsl:call-template>
    <xsl:call-template name="gentext.space"/>
    <xsl:call-template name="dingbat">
      <xsl:with-param name="dingbat">copyright</xsl:with-param>
    </xsl:call-template>
    <xsl:call-template name="gentext.space"/>
    <xsl:call-template name="copyright.years">
      <xsl:with-param name="years" select="year"/>
      <xsl:with-param name="print.ranges" select="$make.year.ranges"/>
      <xsl:with-param name="single.year.ranges"
                      select="$make.single.year.ranges"/>
    </xsl:call-template>
    <xsl:call-template name="gentext.space"/>
    <xsl:apply-templates select="holder" mode="titlepage.mode"/>
    <xsl:if test="following-sibling::copyright">
      <xsl:text>\par&#10;</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- Latex hacking -->
  <xsl:variable name="latex.begindocument">
    <xsl:text>
\usepackage[none]{hyphenat}
\def\DBKshorttile{AFTR Manual}
\def\DBKcheadfront{%
  \begin{tabular}{
    >{\raggedright}p{5.6cm} >{\centering}p{5.6cm} >{\raggedleft}p{5.6cm}} %
    \multirow{3}{5.6cm}{\DBKshorttile}
    &amp; &amp; \textsf{\DBKreference{} \edhead} \tabularnewline%
    &amp; \releasebox &amp; \tabularnewline %
    &amp; &amp; \textsf{\thepage}
  \tabularnewline%
  \end{tabular}%
}
\def\DBKcheadbody{%
  \begin{tabular}{
    >{\raggedright}p{5.6cm} >{\centering}p{5.6cm} >{\raggedleft}p{5.6cm}} %
    \multirow{3}{5.6cm}{\DBKshorttile}
    &amp; &amp; \textsf{\DBKreference{} \edhead} \tabularnewline%
    &amp; \releasebox &amp; \tabularnewline %
    &amp; &amp; \textsf{\thepage{} / \getpagerefnumber{LastPage}}
  \tabularnewline%
  \end{tabular}%
}
\def\DBKcover{
\ifthenelse{\equal{\DBKedition}{}}{\def\edhead{}}{\def\edhead{Ed. \DBKedition}}
% interligne double
\setlength{\oldbaselineskip}{\baselineskip}
\setlength{\baselineskip}{2\oldbaselineskip}
\pagestyle{empty}
\textsf{
\vfill
\vspace{2.5cm}
\begin{center}
  \huge{\textbf{\DBKtitle}}\\ %
\end{center}
\vfill
\setlength{\baselineskip}{\oldbaselineskip}
\begin{center}
  \includegraphics[scale=2]{isc-logo}
\end{center}
}
% Format for the other pages
\newpage
\setlength{\baselineskip}{\oldbaselineskip}
\chead[]{\DBKcheadfront}
\lfoot[]{}
}
\def\DBKlegalblock{
\large {
\begin{center}
</xsl:text><xsl:value-of select="$isc.copyright.text"/><xsl:text>
\end{center}
\vfill
\begin{center}
Internet System Consortium \\
950 Charter Street \\
Redwood City, California \\
USA \\
http://www.isc.org/
\end{center}}
\setcounter{page}{0}
}
\let\stdmaketitle=\maketitle
\def\maketitle{
 \stdmaketitle
 \pagestyle{plain}
}
    </xsl:text>
    <xsl:text>&#10;\begin{document}&#10;</xsl:text>
  </xsl:variable>

  <!-- ignore unsupported refentry/docinfo -->
  <xsl:template match="refentry/docinfo"></xsl:template>

</xsl:stylesheet>

<!-- 
  - Local variables:
  - mode: sgml
  - End:
 -->
