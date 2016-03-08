"use strict";

jQuery(document).ready(function($) {

    var lightbox_class = 'image-popup-fit-width';

    (function() {
        var images = $('.main-content img');
        $.each(images, function(index, i) {
            var image = $(i);
            var anchor = image.attr('src');
            image.wrap('<a class="' + lightbox_class + '" href="' + anchor + '""></a>');
        });
    }());

    (function() {
        $('.' + lightbox_class).magnificPopup({
            type: 'image',
            closeOnContentClick: true,
            closeBtnInside: false,
            fixedContentPos: true,
            mainClass: 'mfp-no-margins mfp-with-zoom', // class to remove default margin from left and right side
            image: {
                verticalFit: true,
            },
            zoom: {
                enabled: true,
                duration: 300, // don't foget to change the duration also in CSS
            },
        });
    }());
});
