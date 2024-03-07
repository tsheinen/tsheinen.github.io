// ty https://github.com/hakimel/css/tree/master/progress-nav
var toc = document.querySelector( '.toc' );
console.log(toc.querySelectorAll( 'li' ))
var tocPath = document.querySelector( '.toc-marker path' );
var tocItems;

// Factor of screen size that the element must cross
// before it's considered visible
var TOP_MARGIN = 0.1,
	BOTTOM_MARGIN = 0.2;

var pathLength;

var lastPathStart,
	lastPathEnd;

window.addEventListener( 'resize', drawPath, false );
window.addEventListener( 'scroll', sync, false );

drawPath();

function drawPath() {

	tocItems = [].slice.call( toc.querySelectorAll( 'li' ) );

	// Cache element references and measurements
	tocItems = tocItems.map( function( item ) {
		var anchor = item.querySelector( 'a' );
		var href = anchor.getAttribute( 'href' );
		var target = document.getElementById( href.slice( href.indexOf("#") + 1 ) );
		return {
			listItem: item,
			anchor: anchor,
			target: target
		};
	} );

	// Remove missing targets
	tocItems = tocItems.filter( function( item ) {
		return !!item.target;
	} );

	var path = [];
	var pathIndent;
	tocItems.forEach( function( item, i ) {

		var x = item.anchor.offsetLeft - 5,
			y = item.anchor.offsetTop,
			height = item.anchor.offsetHeight;

		if( i === 0 ) {
			path.push( 'M', x, y, 'L', x, y + height );
			item.pathStart = 0;
		}
		else {
			// Draw an additional line when there's a change in
			// indent levels
			if( pathIndent !== x ) path.push( 'L', pathIndent, y );

			path.push( 'L', x, y );

			// Set the current path so that we can measure it
			tocPath.setAttribute( 'd', path.join( ' ' ) );
			item.pathStart = tocPath.getTotalLength() || 0;

			path.push( 'L', x, y + height );
		}

		pathIndent = x;

		tocPath.setAttribute( 'd', path.join( ' ' ) );
		item.pathEnd = tocPath.getTotalLength();

	} );

	pathLength = tocPath.getTotalLength();

	sync();

}

function sync() {

	var windowHeight = window.innerHeight;

	var pathStart = pathLength,
		pathEnd = 0;

	var visibleItems = 0;

	tocItems.forEach( function( item, idx ) {

		var top = item.target.getBoundingClientRect().top;
		var bottom;
		if (idx + 1 == tocItems.length) {
			bottom = windowHeight
		} else {
			bottom = tocItems[idx+1].target.getBoundingClientRect().top || windowHeight;
		}

		if( bottom > windowHeight * TOP_MARGIN && top < windowHeight * ( 1 - BOTTOM_MARGIN ) ) {
			pathStart = Math.min( item.pathStart, pathStart );
			pathEnd = Math.max( item.pathEnd, pathEnd );

			visibleItems += 1;

			item.listItem.classList.add( 'visible' );
		}
		else {
			item.listItem.classList.remove( 'visible' );
		}

	} );

	// Specify the visible path or hide the path altogether
	// if there are no visible items
	if( visibleItems > 0 && pathStart < pathEnd ) {
		if( pathStart !== lastPathStart || pathEnd !== lastPathEnd ) {
			tocPath.setAttribute( 'stroke-dashoffset', '1' );
			tocPath.setAttribute( 'stroke-dasharray', '1, '+ pathStart +', '+ ( pathEnd - pathStart ) +', ' + pathLength );
			tocPath.setAttribute( 'opacity', 1 );
		}
	}
	else {
		tocPath.setAttribute( 'opacity', 0 );
	}

	lastPathStart = pathStart;
	lastPathEnd = pathEnd;

}